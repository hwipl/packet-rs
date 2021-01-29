use std::str;

use crate::error::*;
use crate::helpers::*;

// parse labels inside raw packet data starting at offset,
// return list of label indexes and the index of the next message field
// after the labels
pub fn parse_labels(raw: &[u8], offset: usize) -> Result<(Vec<usize>, usize)> {
    let mut i = offset;
    let mut is_reference = false;
    let mut label_indexes = Vec::new();
    let mut next_index = 0;
    loop {
        if i >= raw.len() {
            return Err(DnsError::LabelLength);
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
                return Err(DnsError::LabelReference);
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
pub fn get_name_from_labels(raw: &[u8], label_indexes: &Vec<usize>) -> Result<String> {
    let mut name = String::new();
    for i in label_indexes {
        // get length of current label from first byte
        let length: usize = usize::from(raw[*i]);

        // read domain name part from current label
        let j = i + 1;
        let part = str::from_utf8(&raw[j..j + length]).map_err(|e| DnsError::LabelUtf8(e))?;
        name.push_str(part);
        name += ".";
    }
    return Ok(name);
}

// get the name directly from labels in raw packet starting at offset
pub fn get_name(raw: &[u8], offset: usize) -> Result<String> {
    let (label_indexes, _) = parse_labels(raw, offset)?;
    get_name_from_labels(raw, &label_indexes)
}
