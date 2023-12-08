// Uncomment this block to pass the first stage
use std::{borrow::Cow, net::UdpSocket};

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
    fn deserialize(binarr: &Cow<'_, str>) -> DNSMessage {
        let bindata = &binarr.as_bytes()[0..=12];

        // let mut biniter = binarr.iter().take(12);

        let id = u16::from_be_bytes([bindata[0], bindata[1]]);

        let row = u16::from_be_bytes([bindata[2], bindata[3]]);

        let qr = (row >> 15) as u8;
        let opcode = ((row >> 11) & 15) as u8;
        let aa = ((row >> 10) & 1) as u8;
        let tc = ((row >> 9) & 1) as u8;
        let rd = ((row >> 8) & 1) as u8;
        let ra = ((row >> 7) & 1) as u8;
        let z = ((row >> 4) & 7) as u8;
        let rcode = (row & 15) as u8;

        let qdcount = u16::from_be_bytes([bindata[4], bindata[6]]);
        let ancount = u16::from_be_bytes([bindata[7], bindata[8]]);
        let nscount = u16::from_be_bytes([bindata[9], bindata[10]]);
        let arcount = u16::from_be_bytes([bindata[11], bindata[12]]);

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
                dbg!(&_received_data);
                println!("Received {} bytes from {}", size, source);

                let message = DNSMessage::deserialize(&_received_data);
                dbg!(&message);

                let response = message.header.id.to_be_bytes();
                dbg!(&response);
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
