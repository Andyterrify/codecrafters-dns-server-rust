// Uncomment this block to pass the first stage
use std::{io::Write, net::UdpSocket, vec};

// ## Traits
trait ByteFunc<T> {
    fn deserialize(buf: &mut DataWrapper) -> Option<(T, usize)>;
    fn serialize(&self) -> Option<(Vec<u8>, usize)>;
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
    resources: Vec<DNSResource>,
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
    rcode: RCODE,
}

#[derive(Debug, Clone)]
struct DNSQuery {
    qname: DNSLabel,
    qtype: u16,
    qclass: u16,
}

#[derive(Debug)]
struct DNSResource {
    name: DNSLabel,
    rtype: u16,
    class: u16,
    ttl: u32,
    rdlength: u16,
    rdata: Vec<u8>,
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

#[derive(Debug)]
enum RData {
    IP(),
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
    fn deserialize(buffer: &[u8]) -> DNSMessage {
        let mut data = DataWrapper::new(buffer);

        let mut message = DNSMessage {
            header: DNSHeader::deserialize(&mut data).unwrap().0,
            queries: vec![],
            resources: vec![],
        };

        for _ in [0..message.header.qdcount] {
            match DNSQuery::deserialize(&mut data) {
                Some(q) => message.queries.push(q.0),
                None => todo!(),
            }
        }

        message
    }

    fn serialize(&self) -> Vec<u8> {
        let mut buffer = vec![];

        buffer.extend_from_slice(&self.header.serialize().unwrap().0);

        self.queries.iter().for_each(|q| {
            buffer.extend_from_slice(&q.serialize().unwrap().0);
        });

        self.resources.iter().for_each(|x| {
            buffer.extend_from_slice(&x.serialize().unwrap().0);
        });

        buffer
    }

    fn to_response(&mut self) {
        self.header.to_response();
        match self.header.flags.opcode {
            OPCODE::QUERY => (),
            _ => self.header.flags.rcode = RCODE::NotImplemented
        }
    }
}

impl DNSHeader {
    fn to_response(&mut self) {
        self.flags.qr = true;
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

    fn serialize(&self) -> Option<(Vec<u8>, usize)> {
        let mut buf = vec![];

        self.qname.parts.iter().for_each(|x| {
            buf.push(x.len() as u8);
            buf.write_all(x.as_bytes()).unwrap()
        });

        buf.write(&[0x0]).unwrap();
        buf.write(&self.qtype.to_be_bytes()).unwrap();
        buf.write(&self.qclass.to_be_bytes()).unwrap();

        let len = buf.len();
        Some((buf, len))
    }
}

impl ByteFunc<DNSHeader> for DNSHeader {
    fn deserialize(buf: &mut DataWrapper) -> Option<(DNSHeader, usize)> {
        Some((
            DNSHeader {
                id: buf.get_u16(),
                flags: Flags::deserialize(&mut DataWrapper::new(&[buf.get_u8(), buf.get_u8()]))
                    .unwrap()
                    .0,
                qdcount: buf.get_u16(),
                ancount: buf.get_u16(),
                nscount: buf.get_u16(),
                arcount: buf.get_u16(),
            },
            12,
        ))
    }

    fn serialize(&self) -> Option<(Vec<u8>, usize)> {
        let mut buf = vec![];

        buf.write_all(&self.id.to_be_bytes()).unwrap();

        let flags = self.flags.serialize().unwrap().0;
        buf.extend_from_slice(&flags);

        buf.write_all(&self.qdcount.to_be_bytes()).unwrap();
        buf.write_all(&self.ancount.to_be_bytes()).unwrap();
        buf.write_all(&self.nscount.to_be_bytes()).unwrap();
        buf.write_all(&self.arcount.to_be_bytes()).unwrap();

        Some((buf, 12))
    }
}

impl ByteFunc<Flags> for Flags {
    fn deserialize(doublet: &mut DataWrapper<'_>) -> Option<(Flags, usize)> {
        let doublet = doublet.get_u16();
        Some((
            Flags {
                qr: ((doublet >> 15) as u8) == 1,
                opcode: OPCODE::deserialize(((doublet >> 11) & 15) as u8),
                aa: (((doublet >> 10) & 1) as u8) == 1,
                tc: (((doublet >> 9) & 1) as u8) == 1,
                rd: (((doublet >> 8) & 1) as u8) == 1,
                ra: (((doublet >> 7) & 1) as u8) == 1,
                z: ((doublet >> 4) & 7) as u8,
                rcode: RCODE::deserialize((doublet & 15) as u8),
            },
            2,
        ))
    }

    fn serialize(&self) -> Option<(Vec<u8>, usize)> {
        let data = vec![
            (self.qr as u8) << 7
                | self.opcode.serialize() << 3
                | (self.aa as u8) << 3
                | (self.tc as u8) << 2
                | (self.rd as u8),
            (self.ra as u8) << 7 | self.z << 4 | self.rcode.serialize(),
        ];

        Some((data, 2))
    }
}

impl DNSResource {
    fn deserialize(buf: &mut DataWrapper) -> Option<(DNSResource, usize)> {
        let name = buf.follow_label(true);
        let rtype = buf.get_u16();
        let class = buf.get_u16();
        let ttl = u32::from_be_bytes([buf.get_u8(), buf.get_u8(), buf.get_u8(), buf.get_u8()]);
        let rdlength = buf.get_u16();
        let rdata = buf.take(rdlength as usize);

        let data = DNSResource {
            name,
            rtype,
            class,
            ttl,
            rdlength,
            rdata: vec![],
        };
        Some((data, 1))
    }

    fn serialize(&self) -> Option<(Vec<u8>, usize)> {
        let mut buf = vec![];
        self.name.parts.iter().for_each(|x| {
            dbg!(x.len() as u8);
            dbg!(x);
            buf.write(&[x.len() as u8]).unwrap();
            buf.write_all(x.as_bytes()).unwrap();
        });
        buf.write(&[0]).unwrap();

        buf.write_all(&self.rtype.to_be_bytes()).unwrap();
        buf.write_all(&self.class.to_be_bytes()).unwrap();
        buf.write_all(&self.ttl.to_be_bytes()).unwrap();
        buf.write_all(&self.rdlength.to_be_bytes()).unwrap();

        for i in &self.rdata {
            buf.write(&[*i]).unwrap();
        }

        dbg!(&buf);

        let len = buf.len();
        Some((buf, len))
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

                let mut message = DNSMessage::deserialize(&buf);

                let resource = DNSResource {
                    name: DNSLabel {
                        parts: message.queries.get(0).unwrap().qname.parts.clone()
                    },
                    rtype: 1,
                    class: 1,
                    ttl: 2400,
                    rdlength: 4,
                    rdata: vec![8, 8, 8, 8],
                };

                message.to_response();
                message.header.ancount = 1;
                message.resources.push(resource);

                dbg!(&message);
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
