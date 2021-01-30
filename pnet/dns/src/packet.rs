use std::fmt;

use crate::error::*;
use crate::helpers::*;
use crate::record::*;

pub const DNS_HEADER_LENGTH: usize = 12;

// OpCode:
// a four bit field that specifies kind of query in this
// message. This value is set by the originator of a query
// and copied into the response.  The values are:
// 0               a standard query (QUERY)
// 1               an inverse query (IQUERY)
// 2               a server status request (STATUS)
// 3-15            reserved for future use
pub enum OpCode {
    Query,
    IQuery,
    Status,
    Reserved(u8),
}

impl From<u8> for OpCode {
    fn from(code: u8) -> OpCode {
        match code {
            0 => OpCode::Query,
            1 => OpCode::IQuery,
            2 => OpCode::Status,
            _ => OpCode::Reserved(code),
        }
    }
}

impl From<OpCode> for u8 {
    fn from(opcode: OpCode) -> u8 {
        match opcode {
            OpCode::Query => 0,
            OpCode::IQuery => 1,
            OpCode::Status => 2,
            OpCode::Reserved(code) => code,
        }
    }
}

impl fmt::Display for OpCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            OpCode::Query => write!(f, "0 (query)"),
            OpCode::IQuery => write!(f, "1 (iqery)"),
            OpCode::Status => write!(f, "2 (status)"),
            OpCode::Reserved(value) => write!(f, "{} (reserved)", value),
        }
    }
}

// RCode:
// Response code - this 4 bit field is set as part of
// responses.  The values have the following
// interpretation:
// 0               No error condition
// 1               Format error - The name server was
//                 unable to interpret the query.
// 2               Server failure - The name server was
//                 unable to process this query due to a
//                 problem with the name server.
// 3               Name Error - Meaningful only for
//                 responses from an authoritative name
//                 server, this code signifies that the
//                 domain name referenced in the query does
//                 not exist.
// 4               Not Implemented - The name server does
//                 not support the requested kind of query.
// 5               Refused - The name server refuses to
//                 perform the specified operation for
//                 policy reasons.  For example, a name
//                 server may not wish to provide the
//                 information to the particular requester,
//                 or a name server may not wish to perform
//                 a particular operation (e.g., zone
//                 transfer) for particular data.
// 6-15            Reserved for future use.
pub enum RCode {
    NoError,
    FormatError,
    ServerFailure,
    NameError,
    NotImplemented,
    Refused,
    Reserved(u8),
}

impl From<u8> for RCode {
    fn from(code: u8) -> RCode {
        match code {
            0 => RCode::NoError,
            1 => RCode::FormatError,
            2 => RCode::ServerFailure,
            3 => RCode::NameError,
            4 => RCode::NotImplemented,
            5 => RCode::Refused,
            _ => RCode::Reserved(code),
        }
    }
}

impl From<RCode> for u8 {
    fn from(rcode: RCode) -> u8 {
        match rcode {
            RCode::NoError => 0,
            RCode::FormatError => 1,
            RCode::ServerFailure => 2,
            RCode::NameError => 3,
            RCode::NotImplemented => 4,
            RCode::Refused => 5,
            RCode::Reserved(code) => code,
        }
    }
}

impl fmt::Display for RCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RCode::NoError => write!(f, "0 (no error)"),
            RCode::FormatError => write!(f, "1 (format error)"),
            RCode::ServerFailure => write!(f, "2 (server failure)"),
            RCode::NameError => write!(f, "3 (name error)"),
            RCode::NotImplemented => write!(f, "4 (not implemented)"),
            RCode::Refused => write!(f, "5 (refused)"),
            RCode::Reserved(value) => write!(f, "{} (reserved)", value),
        }
    }
}

// dns packet consists of the following 16 bit fields:
//
// Identification,
// Flags/codes
//   (QR (1 bit),  Opcode (4 bits), AA (1 bit), TC (1 bit), RD (1 bit),
//    RA (1 bit), Z (3 bits), RCODE (4 bits)),
// Number of questions,
// Number of answers,
// Number of authority resource records (RRs)
// Number of additional RRs
//
// use methods to read fields from the packet
pub struct DnsPacket<'a> {
    raw: &'a [u8],

    // dns questions inside the packet
    questions: Vec<DnsQuestion<'a>>,

    // dns answers inside the packet
    answers: Vec<DnsAnswer<'a>>,

    // dns authority resource records inside the packet
    authorities: Vec<DnsAuthority<'a>>,

    // dns additional resource records inside the packet
    additionals: Vec<DnsAdditional<'a>>,
}

impl<'a> DnsPacket<'a> {
    // create a new dns packet from raw packet bytes
    pub fn parse(raw: &'a [u8]) -> Result<DnsPacket<'a>> {
        if raw.len() < DNS_HEADER_LENGTH {
            return Err(DnsError::PacketLength);
        }

        let mut packet = DnsPacket {
            raw: raw,
            questions: Vec::new(),
            answers: Vec::new(),
            authorities: Vec::new(),
            additionals: Vec::new(),
        };
        packet.parse_records()?;

        Ok(packet)
    }

    // parse dns records in the dns packet:
    // find questions, answers, authorities, additionals
    // TODO: improve error handling
    fn parse_records(&mut self) -> Result<()> {
        // parse questions
        let mut offset = DNS_HEADER_LENGTH;
        for _ in 0..self.get_questions() {
            let q = DnsQuestion::parse(self.raw, offset)?;
            offset += q.get_length();
            self.questions.push(q);
        }

        // parse answers
        for _ in 0..self.get_answers() {
            let a = DnsAnswer::parse(self.raw, offset)?;
            offset += a.get_length();
            self.answers.push(a);
        }

        // parse authorities
        for _ in 0..self.get_authorities() {
            let a = DnsAuthority::parse(self.raw, offset)?;
            offset += a.get_length();
            self.authorities.push(a);
        }

        // parse additionals
        for _ in 0..self.get_additionals() {
            let a = DnsAdditional::parse(self.raw, offset)?;
            offset += a.get_length();
            self.additionals.push(a);
        }

        return Ok(());
    }

    // get identification field from packet
    pub fn get_id(&self) -> u16 {
        read_be_u16(&self.raw[0..2])
    }

    // get Query (0)/Response (1) bit from packet
    pub fn get_qr(&self) -> u8 {
        (self.raw[2] & 0b10000000) >> 7
    }

    // get OPCODE bits (4 bits) from packet
    pub fn get_opcode(&self) -> OpCode {
        ((self.raw[2] & 0b01111000) >> 3).into()
    }

    // get Authoritative Answer (AA) bit from packet
    pub fn get_aa(&self) -> u8 {
        (self.raw[2] & 0b00000100) >> 2
    }

    // get TrunCation (TC) bit from packet
    pub fn get_tc(&self) -> u8 {
        (self.raw[2] & 0b00000010) >> 1
    }

    // get Recursion Desired (RD) bit from packet
    pub fn get_rd(&self) -> u8 {
        self.raw[2] & 0b00000001
    }

    // get Recursion Available (RA) bit from packet
    pub fn get_ra(&self) -> u8 {
        (self.raw[3] & 0b10000000) >> 7
    }

    // get reserved (Z) bits (3 bits) from packet
    pub fn get_z(&self) -> u8 {
        (self.raw[3] & 0b01110000) >> 4
    }

    // get response code (RCODE) bits (4 bits) from packet
    pub fn get_rcode(&self) -> RCode {
        (self.raw[3] & 0b00001111).into()
    }

    // get number of questions from packet
    pub fn get_questions(&self) -> u16 {
        read_be_u16(&self.raw[4..6])
    }

    // get number of answers from packet
    pub fn get_answers(&self) -> u16 {
        read_be_u16(&self.raw[6..8])
    }

    // get number of authority resource records from packet
    pub fn get_authorities(&self) -> u16 {
        read_be_u16(&self.raw[8..10])
    }

    // get number of additional resource records from packet
    pub fn get_additionals(&self) -> u16 {
        read_be_u16(&self.raw[10..12])
    }

    // get nth question from packet
    pub fn get_question(&self, nth: usize) -> Option<&DnsQuestion> {
        if nth >= self.questions.len() {
            return None;
        }
        Some(&self.questions[nth])
    }

    // get nth answer from packet
    pub fn get_answer(&self, nth: usize) -> Option<&DnsAnswer> {
        if nth >= self.answers.len() {
            return None;
        }
        Some(&self.answers[nth])
    }

    // get nth authority from packet
    pub fn get_authority(&self, nth: usize) -> Option<&DnsAuthority> {
        if nth >= self.authorities.len() {
            return None;
        }
        Some(&self.authorities[nth])
    }

    // get nth additional from packet
    pub fn get_additional(&self, nth: usize) -> Option<&DnsAdditional> {
        if nth >= self.additionals.len() {
            return None;
        }
        Some(&self.additionals[nth])
    }
}

impl<'a> fmt::Display for DnsPacket<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // dns packet header
        write!(
            f,
            "{{id: {}, qr: {}, opcode: {}, aa: {}, tc: {}, rd: {}, ra: {}, \
            z: {}, rcode: {}, questions: {}, answers: {}, authorities: {}, \
            additionals: {}",
            self.get_id(),
            self.get_qr(),
            self.get_opcode(),
            self.get_aa(),
            self.get_tc(),
            self.get_rd(),
            self.get_ra(),
            self.get_z(),
            self.get_rcode(),
            self.get_questions(),
            self.get_answers(),
            self.get_authorities(),
            self.get_additionals(),
        )?;

        // dns questions
        for i in 0..self.get_questions().into() {
            if let Some(question) = self.get_question(i) {
                write!(f, ", question {}: {}", i, question)?;
            }
        }

        // dns answers
        for i in 0..self.get_answers().into() {
            if let Some(answer) = self.get_answer(i) {
                write!(f, ", answer {}: {}", i, answer)?;
            }
        }

        // dns authorities
        for i in 0..self.get_authorities().into() {
            if let Some(authority) = self.get_authority(i) {
                write!(f, ", authority {}: {}", i, authority)?;
            }
        }

        // dns additionals
        for i in 0..self.get_additionals().into() {
            if let Some(additional) = self.get_additional(i) {
                write!(f, ", additional {}: {}", i, additional)?;
            }
        }

        // closing brackets
        write!(f, "}}")
    }
}
