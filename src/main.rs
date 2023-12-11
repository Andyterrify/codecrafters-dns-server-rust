// Uncomment this block to pass the first stage
use std::{io::Write, net::UdpSocket};

// ## Traits
trait ByteFunc<T> {
    fn deserialize(buf: &mut DataWrapper) -> Option<(T, usize)>;
    fn serialize(&self, buf: &mut [u8]) -> Option<usize>;
}

// ## Structs
struct DataWrapper<'a> {
    data: &'a [u8],
    pos: usize,
    read: usize,
}

#[derive(Debug, Clone)]
struct DNSLabel {
    parts: Vec<String>,
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
    qr: bool,
    opcode: OPCODE,
    aa: bool,
    tc: bool,
    rd: bool,
    ra: bool,
    z: u8,
    rcode: u8,
}

#[derive(Debug, Clone)]
struct DNSQuery {
    qname: DNSLabel,
    qtype: u16,
    qclass: u16,
}

// ## Enums
#[derive(Debug)]
enum OPCODE {
    QUERY,
    IQUERY,
    STATUS,
    RESERVED(u8),
}

#[derive(Debug)]
enum RCODE {
    NoErr,
    FormatErr,
    ServerFail,
    NameErr,
    NotImplemented,
    Refused,
    Reserved(u8),
}

// ## Implementations
impl<'a> DataWrapper<'a> {
    fn new(data: &'a [u8]) -> DataWrapper<'a> {
        DataWrapper {
            data,
            pos: 0,
            read: 0,
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
        self.read += 1;

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
        self.read += amount;
        buf
    }
}

impl ByteFunc<DNSQuery> for DNSQuery {
    fn deserialize(buf: &mut DataWrapper) -> Option<(DNSQuery, usize)> {
        Some((
            DNSQuery {
                qname: buf.follow_label(true),
                qtype: buf.get_u16(),
                qclass: buf.get_u16(),
            },
            buf.read,
        ))
    }

    fn serialize(&self, buf: &mut [u8]) -> Option<usize> {
        let mut buf = vec![];

        self.qname.parts.iter().for_each(|x| {
            buf.push(x.len() as u8);
            buf.write_all(x.as_bytes()).unwrap()
        });

        buf.write(&[0x0]).unwrap();
        buf.write(&self.qtype.to_be_bytes()).unwrap();
        buf.write(&self.qclass.to_be_bytes()).unwrap();

        Some(buf.len())
    }
}

impl OPCODE {
    fn deserialize(bin_code: u8) -> OPCODE {
        match bin_code {
            0 => OPCODE::QUERY,
            1 => OPCODE::IQUERY,
            2 => OPCODE::STATUS,
            n => OPCODE::RESERVED(n),
        }
    }

    fn serialize(&self) -> &u8 {
        match self {
            OPCODE::QUERY => &0x0,
            OPCODE::IQUERY => &0x1,
            OPCODE::STATUS => &0x2,
            OPCODE::RESERVED(n) => n,
        }
    }
}

impl RCODE {
    fn deserialize(bin_code: u8) -> RCODE {
        match bin_code {
            0 => RCODE::NoErr,
            1 => RCODE::FormatErr,
            2 => RCODE::ServerFail,
            3 => RCODE::NameErr,
            4 => RCODE::NotImplemented,
            5 => RCODE::Refused,
            n => RCODE::Reserved(n),
        }
    }

    fn serialize(&self) -> &u8 {
        match self {
            RCODE::NoErr => &0x0,
            RCODE::FormatErr => &0x1,
            RCODE::ServerFail => &0x2,
            RCODE::NameErr => &0x3,
            RCODE::NotImplemented => &0x4,
            RCODE::Refused => &0x5,
            RCODE::Reserved(n) => n,
        }
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
                Some(q) => message.queries.push(q.0),
                None => todo!(),
            }
        }

        dbg!(&message);
        message
    }

    fn serialize(&self) -> Vec<u8> {
        let mut buffer = vec![];
        buffer.write_all(&self.header.serialize()).unwrap();

        self.queries.iter().for_each(|q| {
            let _ = q.serialize(&mut buffer);
        });

        dbg!(&buffer);
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
        self.flags.qr = true;
    }
}

impl Flags {
    fn deserialize(doublet: u16) -> Self {
        Flags {
            qr: ((doublet >> 15) as u8) == 1,
            opcode: OPCODE::deserialize(((doublet >> 11) & 15) as u8),
            aa: (((doublet >> 10) & 1) as u8) == 1,
            tc: (((doublet >> 9) & 1) as u8) == 1,
            rd: (((doublet >> 8) & 1) as u8) == 1,
            ra: (((doublet >> 7) & 1) as u8) == 1,
            z: ((doublet >> 4) & 7) as u8,
            rcode: (doublet & 15) as u8,
        }
    }

    fn serialize(&self) -> Vec<u8> {
        let mut buffer = vec![];
        buffer
            .write(&[(self.qr as u8) << 7
                | self.opcode.serialize() << 3
                | (self.aa as u8) << 3
                | (self.tc as u8) << 2
                | (self.rd as u8)])
            .unwrap();
        buffer
            .write(&[((self.ra as u8) << 7 | self.z << 4 | self.rcode)])
            .unwrap();

        buffer
    }
}

// ## Functions
fn is_pointer(data: &[u8; 2]) -> bool {
    (((data[0] as u16) << 7) | data[1] as u16) & 0xc000 == 0xc000
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
