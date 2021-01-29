use std::fmt;
use std::str;

// use dns error types in result
pub type Result<T> = std::result::Result<T, DnsError>;

// dns error types
#[derive(Debug)]
pub enum DnsError {
    DataLength,
    RecordLength,
    PacketLength,
    CharactersLength,
    CharactersUtf8(str::Utf8Error),
    LabelLength,
    LabelReference,
    LabelUtf8(str::Utf8Error),
}

impl fmt::Display for DnsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DnsError::DataLength => write!(f, "invalid length of data field in record"),
            DnsError::RecordLength => write!(f, "invalid length of record"),
            DnsError::PacketLength => write!(f, "invalid length of packet"),
            DnsError::CharactersLength => write!(f, "invalid length of character string"),
            DnsError::CharactersUtf8(_) => write!(f, "invalid utf8 in character string"),
            DnsError::LabelLength => write!(f, "invalid length of label"),
            DnsError::LabelReference => write!(f, "invalid reference in label"),
            DnsError::LabelUtf8(_) => write!(f, "invalid utf8 in label"),
        }
    }
}
