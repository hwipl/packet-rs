use std::convert::TryInto;
use std::fmt;
use std::str;

use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::Packet;
use pnet::transport::TransportChannelType::Layer4;
use pnet::transport::TransportProtocol::Ipv4;
use pnet::transport::{transport_channel, udp_packet_iter};

const DNS_HEADER_LENGTH: usize = 12;
const DNS_MIN_ANSWER_LENGTH: usize = 11;
const DNS_MIN_QUESTION_LENGTH: usize = 5;
const DNS_PORT: u16 = 53;

// Type/QType
// TYPE fields are used in resource records.  Note that these types are a
// subset of QTYPEs.
//
// TYPE            value and meaning
// A               1 a host address
// NS              2 an authoritative name server
// MD              3 a mail destination (Obsolete - use MX)
// MF              4 a mail forwarder (Obsolete - use MX)
// CNAME           5 the canonical name for an alias
// SOA             6 marks the start of a zone of authority
// MB              7 a mailbox domain name (EXPERIMENTAL)
// MG              8 a mail group member (EXPERIMENTAL)
// MR              9 a mail rename domain name (EXPERIMENTAL)
// NULL            10 a null RR (EXPERIMENTAL)
// WKS             11 a well known service description
// PTR             12 a domain name pointer
// HINFO           13 host information
// MINFO           14 mailbox or mail list information
// MX              15 mail exchange
// TXT             16 text strings
//
// QTYPE fields appear in the question part of a query.  QTYPES are a
// superset of TYPEs, hence all TYPEs are valid QTYPEs.  In addition, the
// following QTYPEs are defined:
//
// AXFR            252 A request for a transfer of an entire zone
// MAILB           253 A request for mailbox-related records (MB, MG or MR)
// MAILA           254 A request for mail agent RRs (Obsolete - see MX)
// *               255 A request for all records
enum Type {
    A,
    Ns,
    Md,
    Mf,
    Cname,
    Soa,
    Mb,
    Mg,
    Mr,
    Null,
    Wks,
    Ptr,
    Hinfo,
    Minfo,
    Mx,
    Txt,
    Aaaa,
    Axfr,
    Mailb,
    Maila,
    All,
    Unknown(u16),
}

impl From<u16> for Type {
    fn from(class: u16) -> Type {
        match class {
            1 => Type::A,
            2 => Type::Ns,
            3 => Type::Md,
            4 => Type::Mf,
            5 => Type::Cname,
            6 => Type::Soa,
            7 => Type::Mb,
            8 => Type::Mg,
            9 => Type::Mr,
            10 => Type::Null,
            11 => Type::Wks,
            12 => Type::Ptr,
            13 => Type::Hinfo,
            14 => Type::Minfo,
            15 => Type::Mx,
            16 => Type::Txt,
            28 => Type::Aaaa,
            252 => Type::Axfr,
            253 => Type::Mailb,
            254 => Type::Maila,
            255 => Type::All,
            unknown => Type::Unknown(unknown),
        }
    }
}

impl fmt::Display for Type {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Type::A => write!(f, "1 (a)"),
            Type::Ns => write!(f, "2 (ns)"),
            Type::Md => write!(f, "3 (md)"),
            Type::Mf => write!(f, "4 (mf)"),
            Type::Cname => write!(f, "5 (cname)"),
            Type::Soa => write!(f, "6 (soa)"),
            Type::Mb => write!(f, "7 (mb)"),
            Type::Mg => write!(f, "8 (mg)"),
            Type::Mr => write!(f, "9 (mr)"),
            Type::Null => write!(f, "10 (null)"),
            Type::Wks => write!(f, "11 (wks)"),
            Type::Ptr => write!(f, "12 (ptr)"),
            Type::Hinfo => write!(f, "13 (hinfo)"),
            Type::Minfo => write!(f, "14 (minfo)"),
            Type::Mx => write!(f, "15 (mx)"),
            Type::Txt => write!(f, "16 (txt)"),
            Type::Aaaa => write!(f, "28 (aaaa)"),
            Type::Axfr => write!(f, "252 (axfr)"),
            Type::Mailb => write!(f, "253 (mailb)"),
            Type::Maila => write!(f, "254 (maila)"),
            Type::All => write!(f, "255 (*)"),
            Type::Unknown(unknown) => write!(f, "{} (unknown)", unknown),
        }
    }
}

// Class/QClass:
//
// CLASS fields appear in resource records.  The following CLASS mnemonics
// and values are defined:
// IN              1 the Internet
// CS              2 the CSNET class (Obsolete - used only for examples in
//                   some obsolete RFCs)
// CH              3 the CHAOS class
// HS              4 Hesiod [Dyer 87]
//
// QCLASS fields appear in the question section of a query.  QCLASS values
// are a superset of CLASS values; every CLASS is a valid QCLASS.  In
// addition to CLASS values, the following QCLASSes are defined:
// *               255 any class
enum Class {
    In,
    Cs,
    Ch,
    Hs,
    Unknown(u16),
}

impl From<u16> for Class {
    fn from(class: u16) -> Class {
        match class {
            1 => Class::In,
            2 => Class::Cs,
            3 => Class::Ch,
            4 => Class::Hs,
            unknown => Class::Unknown(unknown),
        }
    }
}

impl fmt::Display for Class {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Class::In => write!(f, "1 (internet)"),
            Class::Cs => write!(f, "2 (csnet)"),
            Class::Ch => write!(f, "3 (chaos)"),
            Class::Hs => write!(f, "4 (hesiod)"),
            Class::Unknown(unknown) => write!(f, "{} (unknown)", unknown),
        }
    }
}

// Data:
enum Data<'a> {
    A(std::net::Ipv4Addr),
    Ns(String),
    Cname(String),
    Soa(String, String, u32, u32, u32, u32, u32),
    Ptr(String),
    Mx(u16, String),
    Aaaa(std::net::Ipv6Addr),
    Unknown(&'a [u8]),
}

impl<'a> Data<'a> {
    fn parse(raw: &[u8], offset: usize, length: usize, typ: Type, class: Class) -> Data {
        let i = offset;

        // only handle class "internet" packets
        match class {
            Class::In => {}
            _ => return Data::Unknown(&raw[i..i + length]),
        }

        // parse data based on its type
        // TODO: add error handling
        match typ {
            Type::A => Data::A(read_be_u32(&raw[i..i + 4]).into()),
            Type::Ns => Data::Ns(get_name(raw, i)),
            Type::Cname => Data::Cname(get_name(raw, i)),
            Type::Soa => {
                let (mname_labels, i) = parse_labels(raw, i).unwrap();
                let (rname_labels, i) = parse_labels(raw, i).unwrap();
                let mname = get_name_from_labels(raw, &mname_labels);
                let rname = get_name_from_labels(raw, &rname_labels);
                let serial = read_be_u32(&raw[i..i + 4]);
                let refresh = read_be_u32(&raw[i + 4..i + 8]);
                let retry = read_be_u32(&raw[i + 8..i + 12]);
                let expire = read_be_u32(&raw[i + 12..i + 16]);
                let minimum = read_be_u32(&raw[i + 16..i + 20]);
                Data::Soa(mname, rname, serial, refresh, retry, expire, minimum)
            }
            Type::Ptr => Data::Ptr(get_name(raw, i)),
            Type::Mx => {
                let preference = read_be_u16(&raw[i..i + 2]);
                Data::Mx(preference, get_name(raw, i + 2))
            }
            Type::Aaaa => Data::Aaaa(read_be_u128(&raw[i..i + 16]).into()),
            _ => Data::Unknown(&raw[i..i + length]),
        }
    }
}

impl<'a> fmt::Display for Data<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Data::A(addr) => write!(f, "{}", addr),
            Data::Ns(domain) => write!(f, "{}", domain),
            Data::Cname(domain) => write!(f, "{}", domain),
            Data::Soa(mname, rname, serial, refresh, retry, expire, minimum) => write!(
                f, "{{mname: {}, rname: {}, serial: {}, refresh: {}, retry: {}, expire: {}, minimum: {}}}",
                mname, rname, serial, refresh, retry, expire, minimum
            ),
            Data::Ptr(domain) => write!(f, "{}", domain),
            Data::Mx(preference, domain) => write!(f, "{{pref: {}, mx: {}}}", preference, domain),
            Data::Aaaa(addr) => write!(f, "{}", addr),
            Data::Unknown(unknown) => write!(f, "unknown ({:?})", unknown),
        }
    }
}

// common struct for dns records
//
// dns resource records consist of the following fields:
// * Name (variable number of labels terminated by 0 label)
// * Type (16 bits)
// * Class (16 bits)
// * TTL (32 bits)            (not in dns questions)
// * Data Length (16 bits)    (not in dns questions)
// * Data (Data Length bytes) (not in dns questions)
//
// use methods to read fields from dns record;
// be careful to not use ttl, data length and data functions in dns questions!
struct DnsRecord<'a> {
    // raw packet data and offset to resource record inside the packet data
    raw: &'a [u8],
    offset: usize,

    // indexes of labels within the packet
    label_indexes: Vec<usize>,

    // start index of next message fields after labels:
    // * type (2 byte): next_index
    // * class (2 byte): next_index + 2
    // * ttl (4 byte): next_index + 4
    // * data length (2 byte): next_index + 8
    // * data (data length bytes): next_index + 10
    next_index: usize,
}

impl<'a> DnsRecord<'a> {
    // create a new dns resource record from raw packet bytes,
    // parse the dns resource record packet:
    // * find labels in the raw packet bytes,
    // * find first index of next fields in packet:
    //   type, class, ttl, data length, data.
    // TODO: add error handling
    fn parse(raw: &'a [u8], offset: usize) -> Result<DnsRecord<'a>, ()> {
        // check offset and minimum size
        if offset > raw.len() || raw.len() - offset < DNS_MIN_QUESTION_LENGTH {
            println!("short dns answer with length {}", raw.len());
            return Err(());
        }

        // parse labels in packet
        let (label_indexes, next_index) = parse_labels(raw, offset)?;

        // returm dns record
        Ok(DnsRecord {
            raw: raw,
            offset: offset,
            label_indexes: label_indexes,
            next_index: next_index,
        })
    }

    // get the length of the labels in this dns record
    fn get_labels_length(&self) -> usize {
        self.next_index - self.offset
    }

    // get the name from labels inside raw packet bytes
    fn get_name(&self) -> String {
        get_name_from_labels(self.raw, &self.label_indexes)
    }

    // get the type field from raw packet bytes
    fn get_type(&self) -> Type {
        let i = self.next_index;
        read_be_u16(&self.raw[i..i + 2]).into()
    }

    // get the class field from raw packet bytes
    fn get_class(&self) -> Class {
        let i = self.next_index + 2;
        read_be_u16(&self.raw[i..i + 2]).into()
    }

    // get the ttl field from raw packet bytes;
    // note: do not use in dns question
    fn get_ttl(&self) -> u32 {
        let i = self.next_index + 4;
        read_be_u32(&self.raw[i..i + 4])
    }

    // get the data length field from raw packet bytes;
    // note: do not use in dns question
    fn get_data_length(&self) -> u16 {
        let i = self.next_index + 8;
        read_be_u16(&self.raw[i..i + 2])
    }

    // get the data field from raw packet bytes;
    // note: do not use in dns question
    fn get_data(&self) -> Data {
        let i = self.next_index + 10;
        Data::parse(
            self.raw,
            i,
            usize::from(self.get_data_length()),
            self.get_type(),
            self.get_class(),
        )
    }
}

// dns question conists of the following fields:
//
// Name (variable number of labels terminated by 0 label)
// Type (16 bits)
// Class (16 bits)
//
// use methods to read fields from question
struct DnsQuestion<'a> {
    record: DnsRecord<'a>,
}

impl<'a> DnsQuestion<'a> {
    // create a new dns question from raw packet bytes,
    // parse the question packet:
    pub fn parse(raw: &'a [u8], offset: usize) -> Result<DnsQuestion<'a>, ()> {
        // create and return question
        Ok(DnsQuestion {
            record: DnsRecord::parse(raw, offset)?,
        })
    }

    // get the name field from raw packet bytes
    pub fn get_name(&self) -> String {
        self.record.get_name()
    }

    // get the type field from raw packet bytes
    pub fn get_type(&self) -> Type {
        self.record.get_type()
    }

    // get the class field from raw packet bytes
    pub fn get_class(&self) -> Class {
        self.record.get_class()
    }

    // get the length of the question
    pub fn get_length(&self) -> usize {
        self.record.get_labels_length() + 4
    }
}

impl<'a> fmt::Display for DnsQuestion<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{{name: {}, type: {}, class: {}}}",
            self.get_name(),
            self.get_type(),
            self.get_class(),
        )
    }
}

// dns answer consists of the following fields:
//
// Name (variable number of labels terminated by 0 label)
// Type (16 bits)
// Class (16 bits)
// TTL (32 bits)
// Data Length (16 bits)
// Data (Data Length bytes)
//
// use methods to read fields from question
struct DnsAnswer<'a> {
    record: DnsRecord<'a>,
}

impl<'a> DnsAnswer<'a> {
    // create a new dns answer from raw packet bytes,
    // parse the answer packet:
    // find labels in the raw packet bytes,
    // find index of type field,
    // find index of class field,
    // find index of ttl field,
    // find index of data length field,
    // find index of data field.
    // TODO: add error handling
    pub fn parse(raw: &'a [u8], offset: usize) -> Result<DnsAnswer<'a>, ()> {
        if raw.len() - offset < DNS_MIN_ANSWER_LENGTH {
            println!("short dns answer with length {}", raw.len());
            return Err(());
        }

        Ok(DnsAnswer {
            record: DnsRecord::parse(raw, offset)?,
        })
    }

    // get the name field from raw packet bytes
    pub fn get_name(&self) -> String {
        self.record.get_name()
    }

    // get the type field from raw packet bytes
    pub fn get_type(&self) -> Type {
        self.record.get_type()
    }

    // get the class field from raw packet bytes
    pub fn get_class(&self) -> Class {
        self.record.get_class()
    }

    // get the ttl field from raw packet bytes
    pub fn get_ttl(&self) -> u32 {
        self.record.get_ttl()
    }

    // get the data length field from raw packet bytes
    pub fn get_data_length(&self) -> u16 {
        self.record.get_data_length()
    }

    // get the data field from raw packet bytes;
    fn get_data(&self) -> Data {
        self.record.get_data()
    }

    // get the length of the answer
    pub fn get_length(&self) -> usize {
        self.record.get_labels_length() + 10 + usize::from(self.record.get_data_length())
    }
}

impl<'a> fmt::Display for DnsAnswer<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{{name: {}, type: {}, class: {}, ttl: {}, data length: {}, data: {}}}",
            self.get_name(),
            self.get_type(),
            self.get_class(),
            self.get_ttl(),
            self.get_data_length(),
            self.get_data(),
        )
    }
}

// dns authority resource record consists of the same fields as dns answer,
// so reuse DnsAnswer for this
type DnsAuthority<'a> = DnsAnswer<'a>;

// dns additional resource record consists of the same fields as dns answer,
// so reuse DnsAnswer for this
type DnsAdditional<'a> = DnsAnswer<'a>;

// OpCode:
// a four bit field that specifies kind of query in this
// message. This value is set by the originator of a query
// and copied into the response.  The values are:
// 0               a standard query (QUERY)
// 1               an inverse query (IQUERY)
// 2               a server status request (STATUS)
// 3-15            reserved for future use
enum OpCode {
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
enum RCode {
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
struct DnsPacket<'a> {
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
    pub fn parse(raw: &'a [u8]) -> Result<DnsPacket<'a>, ()> {
        if raw.len() < DNS_HEADER_LENGTH {
            println!("short dns packet with length {}", raw.len());
            return Err(());
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
    fn parse_records(&mut self) -> Result<(), ()> {
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

// parse labels inside raw packet data starting at offset,
// return list of label indexes and the index of the next message field
// after the labels
fn parse_labels(raw: &[u8], offset: usize) -> Result<(Vec<usize>, usize), ()> {
    let mut i = offset;
    let mut is_reference = false;
    let mut label_indexes = Vec::new();
    let mut next_index = 0;
    loop {
        if i >= raw.len() {
            return Err(());
        }
        // get length of current label from first byte
        let length: usize = usize::from(raw[i]);

        // have we reached end of labels?
        if length == 0 {
            // if we reached this end of labels while following a
            // label reference, do not update indexes, they have
            // been updated before following the reference
            if is_reference {
                break;
            }

            // save indexes of type, class, ttl, data length, data fields
            next_index = i + 1;
            break;
        }

        // is current label a reference to a previous one?
        if length & 0b11000000 != 0 {
            if !is_reference {
                // this is the first reference in this answer, so this
                // marks the end of this answer's labels;
                // save indexes of type, class, ttl, data length,
                // data fields
                next_index = i + 2;
            }

            // follow reference to previous label
            is_reference = true;
            let raw_index = [raw[i] & 0b00111111, raw[i + 1]];
            let new_i = usize::from(read_be_u16(&raw_index));

            // reference must point to previous label
            if new_i >= i {
                return Err(());
            }
            i = new_i;

            continue;
        }

        // save current label index
        label_indexes.push(i);

        // skip to next label
        i += length + 1;
    }

    // parsing successful
    return Ok((label_indexes, next_index));
}

// get name from labels in raw packet
fn get_name_from_labels(raw: &[u8], label_indexes: &Vec<usize>) -> String {
    let mut name = String::new();
    for i in label_indexes {
        // get length of current label from first byte
        let length: usize = usize::from(raw[*i]);

        // read domain name part from current label
        let j = i + 1;
        let part = match str::from_utf8(&raw[j..j + length]) {
            Ok(part) => part,
            Err(err) => {
                println!("{}", err);
                "<error>"
            }
        };
        name.push_str(part);
        name += ".";
    }
    return name;
}

// get the name directly from labels in raw packet starting at offset
fn get_name(raw: &[u8], offset: usize) -> String {
    let (label_indexes, _) = parse_labels(raw, offset).unwrap();
    get_name_from_labels(raw, &label_indexes)
}

// get dns character string from raw packet data
// TODO: add error handling
fn get_character_strings(raw: &[u8]) -> Vec<String> {
    let mut strings = Vec::new();
    let mut i = 0;

    while i < raw.len() {
        let length = usize::from(raw[i]);
        if i + length > raw.len() {
            break;
        }
        i += 1;
        let chars = str::from_utf8(&raw[i..i + length]).unwrap();
        strings.push(String::from(chars));
        i += length;
    }

    return strings;
}

// convert a 16 bit field from big endian to native byte order
fn read_be_u16(bytes: &[u8]) -> u16 {
    u16::from_be_bytes(bytes.try_into().expect("slice with incorrect length"))
}

// convert a 32 bit field from big endian to native byte order
fn read_be_u32(bytes: &[u8]) -> u32 {
    u32::from_be_bytes(bytes.try_into().expect("slice with incorrect length"))
}

// convert a 128 bit field from big endian to native byte order
fn read_be_u128(bytes: &[u8]) -> u128 {
    u128::from_be_bytes(bytes.try_into().expect("slice with incorrect length"))
}

fn main() {
    // create an udp channel
    let protocol = Layer4(Ipv4(IpNextHeaderProtocols::Udp));
    let (_, mut rx) = match transport_channel(4096, protocol) {
        Ok((tx, rx)) => (tx, rx),
        Err(e) => panic!(
            "An error occurred when creating the transport channel: {}",
            e
        ),
    };

    // read udp packets from channel and handle dns packets
    let mut iter = udp_packet_iter(&mut rx);
    loop {
        match iter.next() {
            Ok((packet, addr)) => {
                // only handle dns packets
                if packet.get_source() != DNS_PORT && packet.get_destination() != DNS_PORT {
                    continue;
                }

                // parse dns packet
                print!("got dns packet from {}: ", addr);
                match DnsPacket::parse(packet.payload()) {
                    Ok(dns) => println!("{}", dns),
                    Err(_) => println!("malformed dns packet"),
                };
            }
            Err(e) => {
                panic!("An error occurred while reading: {}", e);
            }
        }
    }
}
