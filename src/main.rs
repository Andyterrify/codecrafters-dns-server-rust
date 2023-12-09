// Uncomment this block to pass the first stage
use std::{borrow::Cow, io::Write, net::UdpSocket, ops::Deref, panic::PanicInfo, vec};

use bytes::BufMut;

#[derive(Debug)]
struct DNSMessage {
    header: DNSHeader,
}

#[derive(Debug)]
struct DNSHeader {
    id: u16,
    qr: u8,
    opcode: u8,
    aa: u8,
    tc: u8,
    rd: u8,
    ra: u8,
    z: u8,
    rcode: u8,
    qdcount: u16,
    ancount: u16,
    nscount: u16,
    arcount: u16,
}

impl DNSMessage {
    // This implements the header format for RFC 1035
    // Wireshark displays DNS headers as specified in RFC 2535
    fn deserialize(binarr: &[u8]) -> DNSMessage {
        let mut bin_header = binarr.iter();

        let id = u16::from_be_bytes([*bin_header.next().unwrap(), *bin_header.next().unwrap()]);

        let (qr, opcode, aa, tc, rd, ra, z, rcode) =
            DNSMessage::parse_bits([*bin_header.next().unwrap(), *bin_header.next().unwrap()]);

        let qdcount =
            u16::from_be_bytes([*bin_header.next().unwrap(), *bin_header.next().unwrap()]);
        let ancount =
            u16::from_be_bytes([*bin_header.next().unwrap(), *bin_header.next().unwrap()]);
        let nscount =
            u16::from_be_bytes([*bin_header.next().unwrap(), *bin_header.next().unwrap()]);
        let arcount =
            u16::from_be_bytes([*bin_header.next().unwrap(), *bin_header.next().unwrap()]);

        DNSMessage {
            header: DNSHeader {
                id,
                qr,
                opcode,
                aa,
                tc,
                rd,
                ra,
                z,
                rcode,
                qdcount,
                ancount,
                nscount,
                arcount,
            },
        }
    }

    fn parse_bits(twobyte: [u8; 2]) -> (u8, u8, u8, u8, u8, u8, u8, u8) {
        (
            twobyte[0] >> 7,
            (twobyte[0] >> 3) & 15,
            (twobyte[0] >> 2) & 1,
            (twobyte[0] >> 1) & 1,
            twobyte[0] & 1,
            (twobyte[1] >> 7) & 1,
            (twobyte[1] >> 4) & 7,
            twobyte[1] & 15,
        )
    }

    fn serialize(&self) -> Vec<u8> {
        let mut buffer = vec![].writer();
        let header = &self.header;

        dbg!(&header);
        buffer.write_all(&header.id.to_be_bytes()).unwrap();

        buffer
            .write(&[header.qr << 7
                | header.opcode << 3
                | header.aa << 3
                | header.tc << 2
                | header.rd])
            .unwrap();
        buffer
            .write(&[(header.ra << 7 | header.z << 4 | header.rcode)])
            .unwrap();

        buffer.write_all(&header.qdcount.to_be_bytes()).unwrap();
        buffer.write_all(&header.ancount.to_be_bytes()).unwrap();
        buffer.write_all(&header.nscount.to_be_bytes()).unwrap();
        buffer.write_all(&header.arcount.to_be_bytes()).unwrap();

        buffer.into_inner()
    }

    fn to_response(&mut self) {
        self.header.qr = 1
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

                let mut message = DNSMessage::deserialize(&buf);
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
