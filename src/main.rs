// Uncomment this block to pass the first stage
use std::{io::Write, net::UdpSocket};

use rand::seq::index;

struct DataWrapper<'a> {
    data: &'a [u8],
    pos: usize,
}

#[derive(Debug, Clone)]
struct DNSLabel {
    parts: Vec<String>,
}

impl<'a> DataWrapper<'a> {
    fn new(data: &'a [u8]) -> Self {
        DataWrapper { data, pos: 0 }
    }

    fn next(&mut self) -> Option<&u8> {
        if self.pos < self.data.len() {
            let byte = &self.data[self.pos];
            self.pos += 1;
            Some(byte)
        } else {
            None
        }
    }

    fn seek(&mut self, pos: usize) -> Option<()> {
        if pos > self.data.len() {
            None
        } else {
            self.pos = pos;

            Some(())
        }
    }

    fn pos(&self) -> usize {
        self.pos
    }

    fn get_u8(&mut self) -> u8 {
        let byte = self.data[self.pos];
        self.pos += 1;

        byte
    }

    fn get_u16(&mut self) -> u16 {
        u16::from_be_bytes([self.get_u8(), self.get_u8()])
    }

    fn peek(&mut self) -> Option<u8> {
        if self.pos() + 1 > self.data.len() {
            None
        } else {
            Some(self.data[self.pos() + 1])
        }
    }

    fn follow_label(&mut self, follow_pointer: bool) -> DNSLabel {
        let mut byte = self.get_u8();
        let mut dns_label = DNSLabel { parts: vec![] };

        loop {
            if is_pointer(&[byte, self.peek().unwrap()]) & follow_pointer {
                self.follow_pointer(&mut dns_label);
            } else if byte != 0x0 {
                match String::from_utf8(self.take(byte as usize).to_vec()) {
                    Ok(label) => dns_label.parts.push(label),
                    Err(_) => todo!(),
                }
            } else {
                break;
            }

            byte = self.get_u8();
        }

        dns_label
    }

    fn follow_pointer(&mut self, dns_label: &mut DNSLabel) {
        let temp_pointer = self.pos;
        self.seek(self.pos - 1); // move back to beginning of double

        let mut index = self.get_u16() & 0x3FFF;

        loop {
            self.seek(index as usize);

            let label = self.follow_label(false);
            label
                .parts
                .into_iter()
                .for_each(|x| dns_label.parts.push(x));

            self.pos = temp_pointer;

            if self.peek().unwrap() == 0x0 {
                break;
            } else {
                index = self.get_u16() & 0x3FFF;
            }
        }

        todo!()
    }

    fn take(&mut self, amount: usize) -> &[u8] {
        let buf = &self.data[self.pos..self.pos + amount];
        self.seek(self.pos + amount);
        buf
    }
}

fn is_pointer(data: &[u8; 2]) -> bool {
    (((data[0] as u16) << 7) | data[1] as u16) & 0xc000 == 0xc000
}

#[derive(Debug)]
struct DNSMessage {
    header: DNSHeader,
    queries: Vec<DNSQuery>,
}

#[derive(Debug)]
struct DNSHeader {
    id: u16,
    flags: Flags,
    qdcount: u16,
    ancount: u16,
    nscount: u16,
    arcount: u16,
}

#[derive(Debug)]
struct Flags {
    qr: u8,
    opcode: u8,
    aa: u8,
    tc: u8,
    rd: u8,
    ra: u8,
    z: u8,
    rcode: u8,
}

#[derive(Debug, Clone)]
struct DNSQuery {
    qname: DNSLabel,
    qtype: u16,
    qclass: u16,
}

impl DNSQuery {
    fn deserialize(buf: &mut DataWrapper) -> Option<DNSQuery> {
        Some(DNSQuery {
            qname: buf.follow_label(true),
            qtype: buf.get_u16(),
            qclass: buf.get_u16(),
        })
    }
}

impl DNSMessage {
    // This implements the header format for RFC 1035
    // Wireshark displays DNS headers as specified in RFC 2535
    fn deserialize(mut data: DataWrapper) -> DNSMessage {
        let mut message = DNSMessage {
            header: DNSHeader::deserialize(&mut data),
            queries: vec![],
        };

        for _ in [0..message.header.qdcount] {
            match DNSQuery::deserialize(&mut data) {
                Some(q) => message.queries.push(q),
                None => todo!(),
            }
        }

        dbg!(&message);
        message
    }

    fn serialize(&self) -> Vec<u8> {
        let mut buffer = vec![];
        buffer.write_all(&self.header.serialize()).unwrap();

        dbg!(self);

        buffer
    }

    fn to_response(&mut self) {
        self.header.to_response();
    }
}

impl DNSHeader {
    fn deserialize(buf: &mut DataWrapper) -> Self {
        DNSHeader {
            id: buf.get_u16(),
            flags: Flags::deserialize(buf.get_u16()),
            qdcount: buf.get_u16(),
            ancount: buf.get_u16(),
            nscount: buf.get_u16(),
            arcount: buf.get_u16(),
        }
    }
    fn serialize(&self) -> Vec<u8> {
        let mut buffer = vec![];
        buffer.write_all(&self.id.to_be_bytes()).unwrap();

        buffer.write_all(&self.flags.serialize()).unwrap();

        buffer.write_all(&self.qdcount.to_be_bytes()).unwrap();
        buffer.write_all(&self.ancount.to_be_bytes()).unwrap();
        buffer.write_all(&self.nscount.to_be_bytes()).unwrap();
        buffer.write_all(&self.arcount.to_be_bytes()).unwrap();

        buffer
    }
    fn to_response(&mut self) {
        self.flags.qr = 1;
    }
}

impl Flags {
    fn deserialize(doublet: u16) -> Self {
        Flags {
            qr: (doublet >> 15) as u8,
            opcode: ((doublet >> 11) & 15) as u8,
            aa: ((doublet >> 10) & 1) as u8,
            tc: ((doublet >> 9) & 1) as u8,
            rd: ((doublet >> 8) & 1) as u8,
            ra: ((doublet >> 7) & 1) as u8,
            z: ((doublet >> 4) & 7) as u8,
            rcode: (doublet & 15) as u8,
        }
    }
    fn serialize(&self) -> Vec<u8> {
        let mut buffer = vec![];
        buffer
            .write(&[self.qr << 7 | self.opcode << 3 | self.aa << 3 | self.tc << 2 | self.rd])
            .unwrap();
        buffer
            .write(&[(self.ra << 7 | self.z << 4 | self.rcode)])
            .unwrap();

        buffer
    }
}

fn main() {
    // You can use print statements as follows for debugging, they'll be visible when running tests.
    println!("Logs from your program will appear here!");

    // Uncomment this block to pass the first stage
    let udp_socket = UdpSocket::bind("127.0.0.1:2053").expect("Failed to bind to address");
    let mut buf = [0; 512];

    loop {
        match udp_socket.recv_from(&mut buf) {
            Ok((size, source)) => {
                let _received_data = String::from_utf8_lossy(&buf[0..size]);
                println!("Received {} bytes from {}", size, source);

                let data = DataWrapper::new(&buf);

                let mut message = DNSMessage::deserialize(data);

                message.to_response();
                let response = message.serialize();

                udp_socket
                    .send_to(&response, source)
                    .expect("Failed to send response");
            }
            Err(e) => {
                eprintln!("Error receiving data: {}", e);
                break;
            }
        }
    }
}
