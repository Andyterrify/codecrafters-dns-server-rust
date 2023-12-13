// Uncomment this block to pass the first stage
use std::{
    env::args,
    fs::File,
    io::{BufWriter, Write},
    net::UdpSocket,
};

use nom::AsBytes;
use pretty_hex::PrettyHex;

#[derive(Debug)]
struct DNSLabel<'a> {
    parts: Vec<&'a str>,
}
#[derive(Debug, Clone)]
struct DNSQuery {
    qname: Vec<u8>,
    qtype: u16,
    qclass: u16,
}

#[derive(Debug)]
struct DNSResource {
    name: Vec<u8>,
    rtype: u16,
    class: u16,
    ttl: u32,
    rdlength: u16,
    rdata: Vec<u8>,
}

impl DNSResource {
    fn to_wire(&self) -> Vec<u8> {
        let mut buf = vec![];

        buf.extend_from_slice(&self.name);
        buf.extend_from_slice(&self.rtype.to_be_bytes());
        buf.extend_from_slice(&self.class.to_be_bytes());
        buf.extend_from_slice(&self.ttl.to_be_bytes());
        buf.extend_from_slice(&self.rdlength.to_be_bytes());
        buf.extend_from_slice(&self.rdata);

        buf
    }
}

// ## Enums
#[derive(Debug, PartialEq)]
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

impl OPCODE {
    fn from_wire(flags: &u16) -> OPCODE {
        let flags = (flags & 0x7800) >> 11;
        match flags {
            0 => OPCODE::QUERY,
            1 => OPCODE::IQUERY,
            2 => OPCODE::STATUS,
            n => OPCODE::RESERVED(n as u8),
        }
    }

    fn to_wire(&self) -> &u8 {
        match self {
            OPCODE::QUERY => &0x0,
            OPCODE::IQUERY => &0x1,
            OPCODE::STATUS => &0x2,
            OPCODE::RESERVED(n) => n,
        }
    }
}

impl RCODE {
    fn from_wire(flags: &u16) -> RCODE {
        let flags = (flags & 0xF) as u8;
        match flags {
            0 => RCODE::NoErr,
            1 => RCODE::FormatErr,
            2 => RCODE::ServerFail,
            3 => RCODE::NameErr,
            4 => RCODE::NotImplemented,
            5 => RCODE::Refused,
            n => RCODE::Reserved(n),
        }
    }

    fn to_wire(&self) -> &u8 {
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
impl DNSQuery {
    fn from_wire(buf: &mut RawWrapper) -> Option<DNSQuery> {
        Some(DNSQuery {
            qname: buf.name_from_wire(),
            qtype: buf.get_u16(),
            qclass: buf.get_u16(),
        })
    }

    fn to_wire(&self) -> Vec<u8> {
        let mut buf = vec![];

        buf.extend_from_slice(&self.qname);
        buf.extend_from_slice(&self.qtype.to_be_bytes());
        buf.extend_from_slice(&self.qclass.to_be_bytes());

        // dbg!(buf.hex_dump());
        // dbg!(self.qname.hex_dump());
        // dbg!(&self.qtype.to_be_bytes().hex_dump());
        // dbg!(self.qclass.to_be_bytes().hex_dump());

        buf
    }
}

#[derive(Debug)]
struct RawWrapper {
    data: Vec<u8>,
    pos: usize,
    consumed: usize,
}

impl RawWrapper {
    fn new(buf: &[u8]) -> Self {
        RawWrapper {
            data: buf.to_vec(),
            pos: 0,
            consumed: 0,
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
        self.consumed += 1;

        byte
    }

    fn get_u16(&mut self) -> u16 {
        u16::from_be_bytes([self.get_u8(), self.get_u8()])
    }

    fn get_u32(&mut self) -> u32 {
        u32::from_be_bytes([self.get_u8(), self.get_u8(), self.get_u8(), self.get_u8()])
    }

    fn peek(&mut self) -> u8 {
        self.data[self.pos() + 1]
    }

    fn peek_two(&mut self) -> u16 {
        (self.data[self.pos() + 2] as u16) << 8 | self.data[self.pos() + 1] as u16
    }

    fn name_from_wire(&mut self) -> Vec<u8> {
        let mut dns_label = vec![];
        let limit: usize = 64;
        let mut recursion = 0;

        let reference = self.pos();
        let mut marker = reference;
        let mut in_label = true;
        let mut followed_pointer = false;

        let mut byte = self.get_u8();

        loop {
            dbg!("EMPTY LINE");
            dbg!("");

            dbg!(format!("Byte: {:x}", byte));
            if (((byte as u16) << 7 | self.peek() as u16) & 0xc000) == 0xC000 && !followed_pointer {
                dbg!("11111");
                // this is a pointer
                followed_pointer = true;
                recursion += 1;

                if in_label {
                    in_label = false;
                    match self.pos() - reference > 63 {
                        true => dns_label.extend_from_slice(&self.data[reference..reference + 63]),
                        false => dns_label.extend_from_slice(&self.data[reference..self.pos()]),
                    }
                }

                let offset = self.get_u16() & 0x3FF;
                if offset < marker as u16 {
                    self.seek(offset as usize);
                    marker = offset as usize;
                    in_label = true;
                } else {
                    unimplemented!(
                        "Have not implemented chance that reference offset is past start of string"
                    )
                }
            } else if (((byte as u16) << 7 | self.peek() as u16) & 0xc000) == 0xC000 {
                dbg!("22222");
                break;
                // unimplemented!(
                //     "Have not implemented logic in case we run into pointer after pointer"
                // );
            } else if byte == 0 {
                dbg!("33333");
                if in_label {
                    in_label = false;
                    match self.pos() - reference > 63 {
                        true => {
                            dns_label.extend_from_slice(self.take_from(reference, reference + 63))
                        }
                        false => dns_label.extend_from_slice(self.take_from(reference, self.pos())),
                    }
                }
                // dns_label.push(0);

                break;
            } else if in_label {
                dbg!("44444");
                // todo this is a normal string
                let length = byte as usize;
                dbg!("got length", length);
                dbg!(format!(
                    "current_position {}# jumping to {}",
                    self.pos(),
                    self.pos() + length
                ));
                self.seek(self.pos() + length);
                byte = self.get_u8();
                dbg!(format!("next-byte {:x}", byte));
            }
        }

        // dbg!(&dns_label);
        dns_label
    }

    fn take_from(&mut self, start: usize, end: usize) -> &[u8] {
        let buf = &self.data[start..end];
        self.consumed += (end - start);
        buf
    }
}

#[derive(Debug)]
enum Transport {
    TCP,
    UDP,
}

#[derive(Debug)]
struct DNSMessage {
    transport: Transport,
    raw: RawWrapper,
    header: DNSHeader,
    queries: Vec<DNSQuery>,
    ans: Vec<DNSResource>,
    nsr: Vec<DNSResource>,
    arc: Vec<DNSResource>,
}

#[derive(Debug)]
struct DNSHeader {
    id: u16,
    qr: bool,
    opcode: OPCODE,
    aa: bool,
    tc: bool,
    rd: bool,
    ra: bool,
    z: bool,
    ad: bool,
    cd: bool,
    rcode: RCODE,
    qdcount: u16,
    ancount: u16,
    nscount: u16,
    arcount: u16,
}

impl DNSMessage {
    fn new(buf: &[u8]) -> Self {
        DNSMessage {
            transport: Transport::UDP,
            raw: RawWrapper::new(buf),
            header: DNSHeader::shell(),
            queries: vec![],
            ans: vec![],
            nsr: vec![],
            arc: vec![],
        }
    }

    fn from_wire(&mut self) {
        // parse header information
        self.header.from_wire(&mut self.raw);

        // parse queries
        let header = self.header.qdcount;
        let mut queries = vec![];

        for _ in 0..header {
            let a = DNSQuery::from_wire(&mut self.raw).unwrap();
            queries.push(a);
        }

        // dbg!(&self.queries);
        self.queries = queries;

        // dbg!(&self);
    }

    fn process_queries(&mut self, socket: &mut UdpSocket, resolver: Option<&String>) {
        let queries = &self.queries;

        if self.header.opcode != OPCODE::QUERY {
            self.header.rcode = RCODE::NotImplemented
        }

        let mut answers = vec![];

        match resolver {
            Some(res) => {
                let mut buf = [0; 512];

                let q = &self.to_wire();

                socket
                    .send_to(&q, res)
                    .expect("Failed to query resolver");
                socket.recv_from(&mut buf).expect("Failed to read response");

                let response = DNSMessage::new(&buf);
                self.ans = response.ans;
            }
            None => {
                for a in &self.queries {
                    answers.push(DNSResource {
                        name: a.qname.clone(),
                        rtype: 1,
                        class: 1,
                        ttl: 127389,
                        rdlength: 4,
                        rdata: b"\x08\x08\x08\x08".to_vec(),
                    })
                }

                self.header.ancount = answers.len() as u16;
                self.ans = answers;
            }
        }

        self.prepare_answer();
    }

    fn prepare_answer(&mut self) {
        self.header.qr = true;
    }

    fn to_wire(&mut self) -> Vec<u8> {
        let mut buf = vec![];

        let header_wire = self.header.to_wire();
        buf.extend_from_slice(&header_wire);

        for q in &self.queries {
            buf.extend_from_slice(&q.to_wire());
        }

        for ans in &self.ans {
            buf.extend_from_slice(&ans.to_wire());
        }

        buf
    }
}

impl DNSHeader {
    fn shell() -> Self {
        DNSHeader {
            id: rand::random::<u16>(),
            qr: false,
            opcode: OPCODE::RESERVED(99),
            aa: false,
            tc: false,
            rd: false,
            ra: false,
            z: false,
            ad: false,
            cd: false,
            rcode: RCODE::Reserved(0),
            qdcount: 0,
            ancount: 0,
            nscount: 0,
            arcount: 0,
        }
    }
}

impl DNSHeader {
    fn from_wire(&mut self, wrapper: &mut RawWrapper) {
        let id = wrapper.get_u16();

        let flags = wrapper.get_u16();

        self.id = id;
        self.qr = flags >> 15 == 1;
        self.opcode = OPCODE::from_wire(&flags);
        self.aa = (flags & 0x400) >> 10 == 1;
        self.tc = (flags & 0x200) >> 9 == 1;
        self.rd = (flags & 0x100) >> 8 == 1;
        self.ra = (flags & 0x80) >> 7 == 1;
        self.z = (flags & 0x40) >> 6 == 1;
        self.ad = (flags & 0x20) >> 5 == 1;
        self.cd = (flags & 0x10) >> 4 == 1;
        self.rcode = RCODE::from_wire(&flags);
        self.qdcount = wrapper.get_u16();
        self.ancount = wrapper.get_u16();
        self.nscount = wrapper.get_u16();
        self.arcount = wrapper.get_u16();
    }

    fn to_wire(&self) -> Vec<u8> {
        let mut buf = vec![];

        buf.extend_from_slice(&self.id.to_be_bytes());

        let byte = ((self.qr as u16) << 15)
            | ((*self.opcode.to_wire() as u16) << 11)
            | ((self.aa as u16) << 10)
            | ((self.tc as u16) << 9)
            | ((self.rd as u16) << 8)
            | ((self.ra as u16) << 7)
            | ((self.z as u16) << 6)
            | ((self.ad as u16) << 5)
            | ((self.cd as u16) << 4)
            | (*self.rcode.to_wire() as u16);

        buf.extend_from_slice(&byte.to_be_bytes());
        buf.extend_from_slice(&self.qdcount.to_be_bytes());
        buf.extend_from_slice(&self.ancount.to_be_bytes());
        buf.extend_from_slice(&self.nscount.to_be_bytes());
        buf.extend_from_slice(&self.arcount.to_be_bytes());

        buf
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

    let args = args().collect::<Vec<String>>();
    let res_addr = if args.len() > 2 { Some(&args[1]) } else { None };
    let mut res_socket = UdpSocket::bind("0.0.0.0:0").expect("Failed to bind to local");

    loop {
        match udp_socket.recv_from(&mut buf) {
            Ok((size, source)) => {
                let _received_data = String::from_utf8_lossy(&buf[0..size]);

                println!("Received {} bytes from {}", size, source);
                // dbg!(buf);

                // dbg!(buf.hex_dump());
                let mut ndns = DNSMessage::new(&buf);

                ndns.from_wire();
                ndns.process_queries(&mut res_socket, res_addr);

                // dbg!(&ndns);

                let response = ndns.to_wire();

                // dbg!(response.hex_dump());

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
