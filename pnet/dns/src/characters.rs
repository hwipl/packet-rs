use std::str;

use crate::error::*;

// get dns character string from raw packet data
pub fn get_character_strings(raw: &[u8]) -> Result<Vec<String>> {
    let mut strings = Vec::new();
    let mut i = 0;

    while i < raw.len() {
        // check length
        let length = usize::from(raw[i]);
        if i + length > raw.len() {
            return Err(DnsError::CharactersLength);
        }
        i += 1;

        // try to read character string
        let chars = str::from_utf8(&raw[i..i + length]).map_err(|e| DnsError::CharactersUtf8(e))?;

        // add string
        strings.push(String::from(chars));
        i += length;
    }

    return Ok(strings);
}
