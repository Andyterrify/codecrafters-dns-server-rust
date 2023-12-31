#![allow(dead_code)]
#![allow(unused_imports)]
#![allow(unused_variables)]
#![allow(unused_assignments)]

use std::{collections::vec_deque, env::args, fs::File, io::Read, net::UdpSocket};

#[derive(Debug)]
struct BytePacketBufffer {
    buf: [u8; 512],
    pos: usize,
}

impl BytePacketBufffer {
    /// Gives us a fresh buffer to hold the message, and a pointer into the buff
    fn new() -> BytePacketBufffer {
        BytePacketBufffer {
            buf: [0; 512],
            pos: 0,
        }
    }

    /// Current position
    fn pos(&self) -> usize {
        self.pos
    }

    /// Step pointer forward a specific number of bytes
    fn step(&mut self, steps: usize) -> Result<(), ()> {
        self.pos += steps;

        Ok(())
    }

    /// Move pointer to specific position
    fn seek(&mut self, pos: usize) -> Result<(), ()> {
        self.pos = pos;

        Ok(())
    }

    /// Read one u8 and advance pointer
    fn read(&mut self) -> Result<u8, ()> {
        if self.pos >= 512 {
            return Err(());
        }

        let res = self.buf[self.pos];
        self.pos += 1;

        Ok(res)
    }

    /// Get a single u8 without moving pointer
    fn get(&mut self, pos: usize) -> Result<u8, ()> {
        if pos >= 512 {
            return Err(());
        }

        let res = self.buf[self.pos];

        Ok(res)
    }

    /// Get a single u8 without moving pointer
    fn get_range(&mut self, start: usize, len: usize) -> Result<&[u8], ()> {
        if start + len >= 512 {
            return Err(());
        }

        Ok(&self.buf[start..start + len])
    }

    /// Read one u16 and advance pointer
    fn read_u16(&mut self) -> Result<u16, ()> {
        let res = ((self.read()? as u16) << 8) | (self.read()? as u16);

        Ok(res)
    }

    /// Read one u32 and advance pointer
    fn read_u32(&mut self) -> Result<u32, ()> {
        let res = ((self.read_u16()? as u32) << 16) | (self.read_u16()? as u32);

        Ok(res)
    }

    /// Read a qname
    ///
    /// The tricky part: Reading domain names, taking labels into consideration.
    /// Will take something like [3]www[6]google[3]com[0] and append
    /// www.google.com to outstr.
    fn read_qname(&mut self, outstr: &mut String) -> Result<(), ()> {
        let pointer_location = self.pos();

        // Track the number of segments
        let _limit: usize = 64;
        let mut segments = 0;

        // Track if we have jumped and how many times
        let mut jumped: bool = false;
        let _max_jumps = 10;
        let mut jumps_done = 0;

        let mut delimiter = "";

        let mut lpos = self.pos();

        // Loop until we reach a null byte or we hit a segment/jump limit
        loop {
            // We have to assume that the data is untrusted so we need to be
            // paranoid. A message can be formed in which we keep jumping
            // forever and consume CPU cycles
            if jumps_done > _max_jumps {
                return Err(());
            }

            // Now we are at the beginning of a segment
            let segment_len = self.get(lpos)?;

            // If the lenght has the most significant bits set then it must be
            // a pointer
            if (segment_len & 0xC0) == 0xC0 {
                // Update the buffer position to a point past the jump. We don't
                // need to touch it any further
                if !jumped {
                    self.seek(lpos + 2)?;
                }

                // Read another byte, calcualte the offset and perform the jump
                // by updating out local position variable
                let b2 = self.get(lpos + 1)? as u16;
                let offset = ((segment_len as u16) ^ 0xC0) << 8 | b2;
                lpos = offset as usize;

                // indicate that a jumpt was performed
                jumped = true;
                jumps_done += 1;

                continue;
            }
            // The best scenario, reading a single label and appending it to output
            else {
                lpos += 1;

                // names are terminated by an empty label, so if the length is
                // zero we're done
                if segment_len == 0 {
                    break;
                }

                // append the delimiter to our output buffe first
                outstr.push_str(delimiter);

                // Extract the actual ASCII bytes for this segment
                let str_buffer = self.get_range(lpos, segment_len as usize);

                delimiter = ".";

                lpos += segment_len as usize;
            }
        }

        if !jumped {
            self.seek(lpos)?;
        }

        Ok(())
    }
}

#[allow(dead_code, unused_variables, unused_assignments)]
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

#[derive(Debug, Clone)]
struct DNSResource {
    name: Vec<u8>,
    rtype: u16,
    class: u16,
    ttl: u32,
    rdlength: u16,
    rdata: Vec<u8>,
}

impl DNSResource {
    fn shell() -> DNSResource {
        DNSResource {
            name: vec![],
            rtype: 0,
            class: 0,
            ttl: 0,
            rdlength: 0,
            rdata: vec![],
        }
    }

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

    fn from_wire(buf: &mut RawWrapper) -> Option<Self> {
        Some(DNSResource {
            name: buf.name_from_wire(),
            rtype: buf.get_u16(),
            class: buf.get_u16(),
            ttl: buf.get_u32(),
            rdlength: buf.get_u16(),
            rdata: {
                buf.seek(buf.pos() - 2);
                let length = buf.get_u16();

                buf.take_from(buf.pos(), buf.pos() + length as usize)
                    .to_vec()
            },
        })
    }

    fn from_buffer(&mut self, buf: &mut BytePacketBufffer) -> Result<(), ()> {
        let mut s = String::new();

        let res = buf.read_qname(&mut s)?;

        self.name = s.as_bytes().to_vec();
        self.rtype = buf.read_u16()?;
        self.class = buf.read_u16()?;
        self.ttl = buf.read_u32()?;
        self.rdlength = buf.read_u16()?;
        self.rdata = buf.get_range(buf.pos(), self.rdlength as usize)?.to_vec();
        buf.step(self.rdlength as usize);

        Ok(())
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

    fn shell() -> DNSQuery {
        DNSQuery {
            qname: vec![],
            qtype: 0,
            qclass: 0,
        }
    }

    fn from_buffer(&mut self, buf: &mut BytePacketBufffer) -> Result<(), ()> {
        let mut s = String::new();

        let res = buf.read_qname(&mut s);

        self.qname = s.as_bytes().to_vec();

        self.qtype = buf.read_u16()?;
        self.qclass = buf.read_u16()?;

        Ok(())
    }

    fn to_wire(&self) -> Vec<u8> {
        let mut buf = vec![];

        buf.extend_from_slice(&self.qname);
        buf.extend_from_slice(&self.qtype.to_be_bytes());
        buf.extend_from_slice(&self.qclass.to_be_bytes());

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

    fn name_from_wire(&mut self) -> Vec<u8> {
        let mut dns_label = vec![];
        let _limit: usize = 64;
        let mut recursion = 0;

        let reference = self.pos();
        let mut marker = reference;
        let mut in_label = true;
        let mut followed_pointer = false;

        let mut byte = self.get_u8();

        loop {
            if (((byte as u16) << 7 | self.peek() as u16) & 0xc000) == 0xC000 && !followed_pointer {
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
                break;
                // unimplemented!(
                //     "Have not implemented logic in case we run into pointer after pointer"
                // );
            } else if byte == 0 {
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
                // todo this is a normal string
                let length = byte as usize;
                self.seek(self.pos() + length);
                byte = self.get_u8();
            }
        }

        // dbg!(&dns_label);
        dns_label
    }

    fn take_from(&mut self, start: usize, end: usize) -> &[u8] {
        let buf = &self.data[start..end];
        self.consumed += end - start;
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
        let mut queries = vec![];
        let mut answers = vec![];

        for _ in 0..self.header.qdcount {
            dbg!("Processing query...");
            let a = DNSQuery::from_wire(&mut self.raw).unwrap();
            queries.push(a);
        }

        for _ in 0..self.header.ancount {
            let a = DNSResource::from_wire(&mut self.raw).unwrap();
            answers.push(a);
        }

        self.queries = queries;
        self.ans = answers;
    }

    /// Create an empty DNSMessage, used as a shell for initialization
    fn shell() -> DNSMessage {
        DNSMessage {
            transport: Transport::UDP,
            raw: RawWrapper::new(&vec![0]),
            header: DNSHeader::shell(),
            queries: vec![],
            ans: vec![],
            nsr: vec![],
            arc: vec![],
        }
    }

    /// Parse a DNS message from an underlying buffer
    fn from_buffer(buffer: &mut BytePacketBufffer) -> Result<DNSMessage, ()> {
        let mut result = DNSMessage::shell();

        // extract header information
        result.header.from_buffer(buffer)?;

        // extract queries
        for _ in 0..result.header.qdcount {
            let mut queston = DNSQuery::shell();
            queston.from_buffer(buffer)?;
            result.queries.push(queston);
        }

        // extract answers
        for _ in 0..result.header.ancount {
            let mut res = DNSResource::shell();
            res.from_buffer(buffer)?;
            result.ans.push(res);
        }

        todo!()
    }

    fn process_queries(&mut self, socket: &mut UdpSocket, resolver: Option<&String>) {
        let _queries = &self.queries;

        if self.header.opcode != OPCODE::QUERY {
            self.header.rcode = RCODE::NotImplemented
        }

        let mut answers = vec![];
        dbg!(resolver);

        match resolver {
            Some(res) => {
                let mut buf = [0; 512];

                let mut answers = vec![];

                for _ in &self.queries {
                    let mut shell = DNSMessage::new(&[]);
                    shell.queries = vec![self.queries[0].clone()];
                    shell.header.qdcount = 1;
                    let q = shell.to_wire();

                    socket.send_to(&q, res).expect("Failed to query resolver");
                    socket.recv_from(&mut buf).expect("Failed to read response");

                    let mut response = DNSMessage::new(&buf);

                    response.from_wire();
                    dbg!(&response.header);
                    dbg!(&response.queries);
                    dbg!(&response.ans);

                    answers.push(response.ans[0].clone());
                }

                self.ans = answers;
                self.header.ancount = self.ans.len() as u16;
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
        self.header.rcode = match self.header.opcode {
            OPCODE::QUERY => RCODE::NoErr,
            _ => RCODE::NotImplemented,
        }
    }

    fn process_que(&mut self) {
        for q in self.queries.iter() {
            let answer = DNSResource {
                name: q.qname.clone(),
                rtype: 1,
                class: 1,
                ttl: 50,
                rdlength: 4,
                rdata: b"\x08\x08\x08\x08".to_vec(),
            };
            self.ans.push(answer);
            self.header.ancount += 1;
        }
    }

    fn add_fake_answer(&mut self) {
        let answer = DNSResource {
            name: b"\x0ccodecrafters\x02io\x00".to_vec(),
            rtype: 1,
            class: 1,
            ttl: 50,
            rdlength: 4,
            rdata: b"\x08\x08\x08\x08".to_vec(),
        };

        self.ans.push(answer);
        self.header.ancount += 1;
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

    fn from_buffer(&mut self, buffer: &mut BytePacketBufffer) -> Result<(), ()> {
        let id = buffer.read_u16()?;

        let flags = buffer.read_u16()?;

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
        self.qdcount = buffer.read_u16()?;
        self.ancount = buffer.read_u16()?;
        self.nscount = buffer.read_u16()?;
        self.arcount = buffer.read_u16()?;

        Ok(())
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

fn main() {
    // You can use print statements as follows for debugging, they'll be visible when running tests.
    println!("Logs from your program will appear here!");

    // Uncomment this block to pass the first stage
    let udp_socket = UdpSocket::bind("127.0.0.1:2053").expect("Failed to bind to address");
    let mut buf = [0; 512];

    // let args = args().collect::<Vec<String>>();
    // // let res_addr = if args.len() == 3 { Some(&args[2]) } else { None };
    // let mut res_socket = UdpSocket::bind("0.0.0.0:0").expect("Failed to bind to local");

    // let mut res_addr = None;

    // for arg in std::env::args() {
    //     if arg == "--resolver" {
    //         res_addr = Some(std::env::args().nth(2).unwrap());
    //     }
    // }

    // let mut f = File::open("query_raw.txt").unwrap();
    // let mut buffer = [0; 512];
    // let a = f.read(&mut buffer).unwrap();
    // dbg!(buffer);
    //
    // let mut ndns = DNSMessage::new(&buffer);
    // ndns.from_wire();
    // dbg!(ndns);

    loop {
        match udp_socket.recv_from(&mut buf) {
            Ok((size, source)) => {
                let _received_data = String::from_utf8_lossy(&buf[0..size]);

                println!("Received {} bytes from {}", size, source);
                // dbg!(buf);

                // dbg!(buf.hex_dump());
                let mut ndns = DNSMessage::new(&buf);

                let mut dns_buf = BytePacketBufffer::new();
                dns_buf.buf = buf;

                ndns.from_wire();
                // ndns.process_queries(&mut res_socket, res_addr.as_ref());

                // dbg!(&ndns);

                ndns.prepare_answer();
                // ndns.add_fake_answer();
                ndns.process_que();

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
