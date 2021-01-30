use std::fmt;

use crate::characters::*;
use crate::error::*;
use crate::helpers::*;
use crate::labels::*;

const DNS_MIN_ANSWER_LENGTH: usize = 11;
const DNS_MIN_QUESTION_LENGTH: usize = 5;

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
pub enum Type {
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
    Srv,
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
            33 => Type::Srv,
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
            Type::Srv => write!(f, "33 (srv)"),
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
pub enum Class {
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
pub enum Data<'a> {
    // implemented types
    A(std::net::Ipv4Addr),
    Ns(String),
    Cname(String),
    Soa(String, String, u32, u32, u32, u32, u32),
    Ptr(String),
    Mx(u16, String),
    Txt(Vec<String>),
    Aaaa(std::net::Ipv6Addr),
    Srv(u16, u16, u16, String),

    // non-existent types for:
    // unknown/not implemented data type, invalid/erroneous data
    Unknown(&'a [u8]),
    Invalid(&'a [u8]),
}

impl<'a> Data<'a> {
    fn parse(raw: &[u8], offset: usize, length: usize, typ: Type, class: Class) -> Result<Data> {
        let i = offset;

        // check offset and data length
        if i + length > raw.len() {
            return Err(DnsError::DataLength);
        }

        // only handle class "internet" packets
        match class {
            Class::In => {}
            _ => return Ok(Data::Unknown(&raw[i..i + length])),
        }

        // parse data based on its type
        // TODO: add error handling
        match typ {
            Type::A => {
                if length != 4 {
                    return Err(DnsError::DataLength);
                }
                Ok(Data::A(read_be_u32(&raw[i..i + 4]).into()))
            }
            Type::Ns => Ok(Data::Ns(get_name(raw, i)?)),
            Type::Cname => Ok(Data::Cname(get_name(raw, i)?)),
            Type::Soa => {
                // check minimum soa data length: 2*label + 5*u32
                if length < 22 {
                    return Err(DnsError::DataLength);
                }
                let (mname_labels, i) = parse_labels(raw, i)?;
                let (rname_labels, i) = parse_labels(raw, i)?;
                let mname = get_name_from_labels(raw, &mname_labels)?;
                let rname = get_name_from_labels(raw, &rname_labels)?;
                let serial = read_be_u32(&raw[i..i + 4]);
                let refresh = read_be_u32(&raw[i + 4..i + 8]);
                let retry = read_be_u32(&raw[i + 8..i + 12]);
                let expire = read_be_u32(&raw[i + 12..i + 16]);
                let minimum = read_be_u32(&raw[i + 16..i + 20]);
                Ok(Data::Soa(
                    mname, rname, serial, refresh, retry, expire, minimum,
                ))
            }
            Type::Ptr => Ok(Data::Ptr(get_name(raw, i)?)),
            Type::Mx => {
                // check minimum mx data length: 1*u16 + 1*label
                if length < 3 {
                    return Err(DnsError::DataLength);
                }
                let preference = read_be_u16(&raw[i..i + 2]);
                Ok(Data::Mx(preference, get_name(raw, i + 2)?))
            }
            Type::Txt => Ok(Data::Txt(get_character_strings(&raw[i..i + length])?)),
            Type::Aaaa => {
                if length != 16 {
                    return Err(DnsError::DataLength);
                }
                Ok(Data::Aaaa(read_be_u128(&raw[i..i + 16]).into()))
            }
            Type::Srv => {
                // check minimum srv data length: 3*u16 + 1*label
                if length < 7 {
                    return Err(DnsError::DataLength);
                }
                let priority = read_be_u16(&raw[i..i + 2]);
                let weight = read_be_u16(&raw[i + 2..i + 4]);
                let port = read_be_u16(&raw[i + 4..i + 6]);
                let target = get_name(raw, i + 6)?;
                Ok(Data::Srv(priority, weight, port, target))
            }
            _ => Ok(Data::Unknown(&raw[i..i + length])),
        }
    }

    fn get(raw: &[u8], offset: usize, length: usize, typ: Type, class: Class) -> Data {
        match Data::parse(raw, offset, length, typ, class) {
            Ok(data) => data,
            Err(_) => Data::Invalid(&raw[offset..offset + std::cmp::min(length, raw.len())]),
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
            Data::Txt(texts) => write!(f, "{:?}", texts),
            Data::Aaaa(addr) => write!(f, "{}", addr),
            Data::Srv(priority, weight, port, target) => write!(f,
                "{{priority: {}, weight: {}, port: {}, target: {}}}", priority, weight, port, target),
            Data::Unknown(unknown) => write!(f, "unknown ({:?})", unknown),
            Data::Invalid(invalid) => write!(f, "invalid ({:?})", invalid),
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
pub struct DnsRecord<'a> {
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
    pub fn parse(raw: &'a [u8], offset: usize) -> Result<DnsRecord<'a>> {
        // check offset and minimum size
        if offset > raw.len() || raw.len() - offset < DNS_MIN_QUESTION_LENGTH {
            return Err(DnsError::RecordLength);
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
    pub fn get_labels_length(&self) -> usize {
        self.next_index - self.offset
    }

    // get the name from labels inside raw packet bytes
    pub fn get_name(&self) -> String {
        get_name_from_labels(self.raw, &self.label_indexes).unwrap_or(String::from("<error>"))
    }

    // get the type field from raw packet bytes
    pub fn get_type(&self) -> Type {
        let i = self.next_index;
        read_be_u16(&self.raw[i..i + 2]).into()
    }

    // get the class field from raw packet bytes
    pub fn get_class(&self) -> Class {
        let i = self.next_index + 2;
        read_be_u16(&self.raw[i..i + 2]).into()
    }

    // get the ttl field from raw packet bytes;
    // note: do not use in dns question
    pub fn get_ttl(&self) -> u32 {
        let i = self.next_index + 4;
        read_be_u32(&self.raw[i..i + 4])
    }

    // get the data length field from raw packet bytes;
    // note: do not use in dns question
    pub fn get_data_length(&self) -> u16 {
        let i = self.next_index + 8;
        read_be_u16(&self.raw[i..i + 2])
    }

    // get the data field from raw packet bytes;
    // note: do not use in dns question
    pub fn get_data(&self) -> Data {
        let i = self.next_index + 10;
        Data::get(
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
pub struct DnsQuestion<'a> {
    record: DnsRecord<'a>,
}

impl<'a> DnsQuestion<'a> {
    // create a new dns question from raw packet bytes,
    // parse the question packet:
    pub fn parse(raw: &'a [u8], offset: usize) -> Result<DnsQuestion<'a>> {
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
pub struct DnsAnswer<'a> {
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
    pub fn parse(raw: &'a [u8], offset: usize) -> Result<DnsAnswer<'a>> {
        if raw.len() - offset < DNS_MIN_ANSWER_LENGTH {
            return Err(DnsError::RecordLength);
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
pub type DnsAuthority<'a> = DnsAnswer<'a>;

// dns additional resource record consists of the same fields as dns answer,
// so reuse DnsAnswer for this
pub type DnsAdditional<'a> = DnsAnswer<'a>;
