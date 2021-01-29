use std::convert::TryInto;

// convert a 16 bit field from big endian to native byte order
pub fn read_be_u16(bytes: &[u8]) -> u16 {
    u16::from_be_bytes(bytes.try_into().expect("slice with incorrect length"))
}

// convert a 32 bit field from big endian to native byte order
pub fn read_be_u32(bytes: &[u8]) -> u32 {
    u32::from_be_bytes(bytes.try_into().expect("slice with incorrect length"))
}

// convert a 128 bit field from big endian to native byte order
pub fn read_be_u128(bytes: &[u8]) -> u128 {
    u128::from_be_bytes(bytes.try_into().expect("slice with incorrect length"))
}
