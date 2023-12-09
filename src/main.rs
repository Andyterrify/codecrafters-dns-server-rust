// Uncomment this block to pass the first stage
use std::{io::Write, net::UdpSocket};

use bytes::{Buf, BufMut};

#[derive(Debug)]
struct DNSMessage {
    header: DNSHeader,
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

impl DNSMessage {
    // This implements the header format for RFC 1035
    // Wireshark displays DNS headers as specified in RFC 2535
    fn deserialize(binarr: &[u8]) -> DNSMessage {
        let header = DNSHeader::deserialize(binarr.take(12).into_inner());

        dbg!(header.qdcount);

        DNSMessage { header }
    }

    fn serialize(&self) -> Vec<u8> {
        let mut buffer = vec![].writer();
        buffer.write_all(&self.header.serialize()).unwrap();

        buffer.into_inner()
    }

    fn to_response(&mut self) {
        self.header.to_response();
    }
}

impl DNSHeader {
    fn deserialize(bin_header: &[u8]) -> Self {
        DNSHeader {
            id: u16::from_be_bytes([bin_header[0], bin_header[1]]),
            flags: Flags::deserialize([bin_header[2], bin_header[3]]),
            qdcount: u16::from_be_bytes([bin_header[4], bin_header[5]]),
            ancount: u16::from_be_bytes([bin_header[6], bin_header[7]]),
            nscount: u16::from_be_bytes([bin_header[8], bin_header[9]]),
            arcount: u16::from_be_bytes([bin_header[10], bin_header[11]]),
        }
    }
    fn serialize(&self) -> Vec<u8> {
        let mut buffer = vec![].writer();
        buffer.write_all(&self.id.to_be_bytes()).unwrap();

        buffer.write_all(&self.flags.serialize()).unwrap();

        buffer.write_all(&self.qdcount.to_be_bytes()).unwrap();
        buffer.write_all(&self.ancount.to_be_bytes()).unwrap();
        buffer.write_all(&self.nscount.to_be_bytes()).unwrap();
        buffer.write_all(&self.arcount.to_be_bytes()).unwrap();

        buffer.into_inner()
    }
    fn to_response(&mut self) {
        self.flags.qr = 1;
    }
}

impl Flags {
    fn deserialize(twobyte: [u8; 2]) -> Self {
        Flags {
            qr: twobyte[0] >> 7,
            opcode: (twobyte[0] >> 3) & 15,
            aa: (twobyte[0] >> 2) & 1,
            tc: (twobyte[0] >> 1) & 1,
            rd: twobyte[0] & 1,
            ra: (twobyte[1] >> 7) & 1,
            z: (twobyte[1] >> 4) & 7,
            rcode: twobyte[1] & 15,
        }
    }
    fn serialize(&self) -> Vec<u8> {
        let mut buffer = vec![].writer();
        buffer
            .write(&[self.qr << 7 | self.opcode << 3 | self.aa << 3 | self.tc << 2 | self.rd])
            .unwrap();
        buffer
            .write(&[(self.ra << 7 | self.z << 4 | self.rcode)])
            .unwrap();

        buffer.into_inner()
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

                dbg!(buf
                    .iter()
                    .map(|x| format!("{:x}", x))
                    .collect::<String>());

                let mut message = DNSMessage::deserialize(&buf);

                message.to_response();
                let response = message.serialize();

                dbg!(response
                    .iter()
                    .map(|x| format!("{:x}", x))
                    .collect::<String>());

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
