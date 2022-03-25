use std::fs::File;
use std::io::{BufRead, BufReader};

///Casts a hex digit (of either case) to a byte value from 0-15.
///Will panic if an illegal digit is passed.
fn hex_digit_to_byte(digit: char) -> u8 {
    if !(digit >= '0' && digit <= '9')
        && !(digit >= 'a' && digit <= 'f')
        && !(digit >= 'A' && digit <= 'F') {
        std::panic!("Illegal hex digit {}", digit);
    }
    return if digit >= '0' && digit <= '9' {
        (digit as u8) - ('0' as u8)
    }
    else if digit >= 'a' && digit <= 'f' {
        (digit as u8) - ('a' as u8) + 10
    }
    else {
        (digit as u8) - ('A' as u8) + 10
    }
}

///Casts a byte value from 0-15 to the corresponding hex digit (0-f) as a char.
///Will panic if an illegal value is passed.
fn byte_to_hex_digit(byte: u8) -> char {
    if byte >= 16 {
        std::panic!("Illegal hex value {}", byte);
    }
    return if byte < 10 {
        (byte + '0' as u8) as char
    } else {
        (byte - 10 + 'a' as u8) as char
    }
}

///Casts a base-64 digit to a byte value from 0-63.
///Will panic if an illegal digit is passed.
fn base_64_digit_to_byte(digit: char) -> u8 {
    if !(digit >= 'A' && digit <= 'Z')
        && !(digit >= 'a' && digit <= 'z')
        && !(digit >= '0' && digit <= '9')
        && digit != '+' && digit != '/' {
        std::panic!("Illegal base64 digit {}", digit);
    }
    return if digit >= 'A' && digit <= 'Z' {
        (digit as u8) - ('A' as u8)
    }
    else if digit >= 'a' && digit <= 'z' {
        (digit as u8) - ('a' as u8) + 26
    }
    else if digit >= '0' && digit <= '9' {
        (digit as u8) - ('0' as u8) + 52
    }
    else if digit == '+' {
        62
    }
    else {
        63
    }
}

///Gets the base64 digit corresponding to a byte value.
///Will panic if an illegal value is passed.
fn byte_to_base_64_digit(digit: u8) -> char {
    if digit > 63 {
        panic!("Illegal base64 value {}", digit);
    }
    return if digit < 26 {
        (digit + 'A' as u8) as char
    }
    else if digit >= 26 && digit < 52 {
        (digit - 26 + 'a' as u8) as char
    }
    else if digit >= 52 && digit < 62 {
        (digit - 52 + '0' as u8) as char
    }
    else if digit == 62 {
        '+'
    }
    else {
        '/'
    }
}

///Takes a hex string and parses it into a vector of bytes
pub fn hex_to_bytes(hex: &str) -> Vec<u8> {
    //Guarantee the hex string has an even number of digits
    if hex.len() % 2 != 0 {
        let mut padded = String::from("0");
        padded.push_str(hex);
        return hex_to_bytes(&padded);
    }

    let mut ret: Vec<u8> = vec![];
    let mut first_digit: bool = true;
    let mut prev_digit: u8 = 0;

    for digit in hex.chars() {
        if first_digit {
            prev_digit = hex_digit_to_byte(digit);
            first_digit = false;
        }
        else {
            ret.push(prev_digit * 16 + hex_digit_to_byte(digit));
            first_digit = true;
        }
    }

    return ret;
}

///Takes a byte vector and parses into a hex string
pub fn bytes_to_hex(bytes: &Vec<u8>) -> String {
    let mut hex: String = String::from("");

    for byte in bytes {
        hex.push(byte_to_hex_digit(byte / 16));
        hex.push(byte_to_hex_digit(byte % 16));
    }

    if hex.starts_with("0") {
        hex = hex[1..].to_string();
    }
    return hex;
}

///Converts an ASCII string to the corresponding bytes
pub fn ascii_to_bytes(ascii: &str) -> Vec<u8> {
    let mut bytes: Vec<u8> = vec![];

    for c in ascii.chars() {
        bytes.push(c as u8);
    }

    return bytes;
}

///Processes a byte vector into the corresponding ASCII string
pub fn bytes_to_ascii(bytes: &Vec<u8>) -> String {
    let mut ascii: String = String::from("");

    for byte in bytes {
        ascii.push(*byte as char);
    }

    return ascii;
}

///Decodes a Base64 string to the corresponding bytes
pub fn base64_to_bytes(base64: &str) -> Vec<u8> {
    //If base-64 string is not padded, add padding in and recurse
    if base64.len() % 4 != 0 {
        let mut padded = String::from(base64);
        padded.push_str(&"=".repeat(4 - base64.len() % 4));
        return base64_to_bytes(&padded);
    }

    let mut bytes: Vec<u8> = vec![];
    let mut pad = 0;
    let mut it = base64.chars();
    let mut digits: [char; 4] = ['0'; 4];
    let mut values: [u8; 4] = [0 as u8; 4];

    if base64.ends_with("==") {
        pad = 2;
    }
    else if base64.ends_with("=") {
        pad = 1;
    }

    let len = base64.len() - pad;

    //For each quartet of characters, calculate the corresponding byte triplet and append
    for _i in 0..len/4 {
        for j in 0..4 {
            match it.next() {
                Some(c) => digits[j] = c,
                None => panic!("Walked off end of string!")
            }
            values[j] = base_64_digit_to_byte(digits[j]);
        }
        bytes.push((values[0] << 2) + (values[1] >> 4));
        bytes.push((values[1] << 4) + (values[2] >> 2));
        bytes.push((values[2] << 6) + values[3]);
    }

    //Separate handling for padded quartet if present
    if pad > 0 {
        for i in 0..(4 - pad) {
            match it.next() {
                Some(c) => digits[i] = c,
                None => panic!("Walked off end of string!")
            }
            values[i] = base_64_digit_to_byte(digits[i]);
        }

        bytes.push((values[0] << 2) + (values[1] >> 4));
        if pad == 1 {
            bytes.push((values[1] << 4) + (values[2] >> 2));
        }
    }

    return bytes;
}

///Processes a byte vector into the corresponding Base64 string
pub fn bytes_to_base64(bytes: &Vec<u8>) -> String {
    let mut base64: String = String::from("");
    if bytes.len() == 0 {
        return base64;
    }

    //Compute needed padding
    let mut pad= 3 - (bytes.len() % 3);
    if pad == 3 {
        pad = 0;
    }
    let block_len = bytes.len() - (2 - pad + 1); //Points to first byte in final 3-byte block

    //For each full byte trio, compute the Base64 digit quartet and append
    for i in 0..bytes.len() / 3 {
        let d1 = (bytes[3*i] >> 2) & 0x3f;
        let d2 = ((bytes[3*i] << 4) & 0x3f) + ((bytes[3*i+1] >> 4) & 0x0f);
        let d3 = ((bytes[3*i+1] << 2) & 0x3f) + ((bytes[3*i+2] >> 6) & 0x03);
        let d4 = bytes[3*i+2] % 64;
        base64.push(byte_to_base_64_digit(d1));
        base64.push(byte_to_base_64_digit(d2));
        base64.push(byte_to_base_64_digit(d3));
        base64.push(byte_to_base_64_digit(d4));
    }

    //Special handling for incomplete byte trio
    if pad > 0 {
        let d1 = (bytes[block_len] >> 2) & 0x3f;
        base64.push(byte_to_base_64_digit(d1));

        if pad == 1 {
            let d2 = ((bytes[block_len] << 4) & 0x3f) + ((bytes[block_len+1] >> 4) & 0x0f);
            let d3 = (bytes[block_len+1] << 2) & 0x3f;
            base64.push(byte_to_base_64_digit(d2));
            base64.push(byte_to_base_64_digit(d3));
        }
        else {
            let d2 = (bytes[block_len] << 4) & 0x3f;
            base64.push(byte_to_base_64_digit(d2));
        }
    }

    //Add padding to string and return
    base64.push_str(&"=".repeat(pad));

    return base64;
}

///Reads a file as a series of newline-separated base64 strings,
///and returns a list of byte vectors equivalent to the file.
///Panics if the file cannot be found or a read error occurs.
pub fn base64_file_to_bytes_by_line(filename: &str) -> Vec<Vec<u8>> {
    let file = File::open(filename);
    let mut bytes = vec![];
    match file {
        Err(_) => panic!("File not found - terminating."),
        Ok(f) => {
            let reader = BufReader::new(f);

            //Read base-64 value on each line and append
            for line in reader.lines() {
                match line {
                    Err(_) => panic!("Read error - terminating."),
                    Ok(l) => bytes.push(base64_to_bytes(&l))
                }
            }
            return bytes;
        }
    }
}

///Reads a file as a single base64 string, and returns an equivalent byte vector.
///Panics if the file cannot be found or a read error occurs.
pub fn base64_file_to_bytes_as_single(filename: &str) -> Vec<u8> {
    let file = File::open(filename);
    match file {
        Err(_) => panic!("File not found - terminating."),
        Ok(f) => {
            let reader = BufReader::new(f);
            let mut base64= String::from("");

            //Read base-64 value across multiple lines
            for line in reader.lines() {
                match line {
                    Err(_) => panic!("Read error - terminating."),
                    Ok(l) => base64 += &l
                }
            }
            return base64_to_bytes(&base64);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hex_to_bytes_base() {
        let hex = "af31";
        let bytes: Vec<u8> = vec![175, 49];

        assert_eq!(hex_to_bytes(hex), bytes);
    }

    #[test]
    fn test_hex_to_bytes_extension() {
        let hex = "0f31";
        let bytes: Vec<u8> = vec![15, 49];

        assert_eq!(hex_to_bytes(hex), bytes);
    }

    #[test]
    #[should_panic(expected="Illegal hex digit h")]
    fn test_hex_to_bytes_error() {
        let hex = "0fh1";
        hex_to_bytes(hex);
    }

    #[test]
    fn test_bytes_to_hex_base() {
        let hex = "af31";
        let bytes: Vec<u8> = vec![175, 49];

        assert_eq!(bytes_to_hex(&bytes), hex);
    }

    #[test]
    fn test_bytes_to_hex_trim() {
        let hex = "f31";
        let bytes: Vec<u8> = vec![15, 49];

        assert_eq!(bytes_to_hex(&bytes), hex);
    }

    #[test]
    fn test_ascii_to_bytes() {
        let test = "Hello";
        let bytes: Vec<u8> = vec![72, 101, 108, 108, 111];

        assert_eq!(ascii_to_bytes(test), bytes);
    }

    #[test]
    fn test_bytes_to_ascii() {
        let test = "Hello";
        let bytes: Vec<u8> = vec![72, 101, 108, 108, 111];

        assert_eq!(bytes_to_ascii(&bytes), test);
    }

    #[test]
    fn test_base64_to_bytes() {
        let b1 = ascii_to_bytes("any carnal pleasur");
        let b2 = ascii_to_bytes("any carnal pleasure");
        let b3 = ascii_to_bytes("any carnal pleasure.");
        let s1 = "YW55IGNhcm5hbCBwbGVhc3Vy";
        let s2 = "YW55IGNhcm5hbCBwbGVhc3VyZQ==";
        let s3 = "YW55IGNhcm5hbCBwbGVhc3VyZS4=";
        let s4 = "YW55IGNhcm5hbCBwbGVhc3VyZQ";
        assert_eq!(base64_to_bytes(s1), b1);
        assert_eq!(base64_to_bytes(s2), b2);
        assert_eq!(base64_to_bytes(s3), b3);
        assert_eq!(base64_to_bytes(s4), b2);
    }

    #[test]
    #[should_panic(expected="Illegal base64 digit <")]
    fn test_base64_to_bytes_error() {
        let s = "<>!*''#";
        base64_to_bytes(s);
    }

    #[test]
    fn test_bytes_to_base64() {
        let b1 = ascii_to_bytes("any carnal pleasur");
        let b2 = ascii_to_bytes("any carnal pleasure");
        let b3 = ascii_to_bytes("any carnal pleasure.");
        let s1 = "YW55IGNhcm5hbCBwbGVhc3Vy";
        let s2 = "YW55IGNhcm5hbCBwbGVhc3VyZQ==";
        let s3 = "YW55IGNhcm5hbCBwbGVhc3VyZS4=";
        assert_eq!(bytes_to_base64(&b1), s1);
        assert_eq!(bytes_to_base64(&b2), s2);
        assert_eq!(bytes_to_base64(&b3), s3);
    }

    #[test]
    fn test_base64_file_to_bytes_by_line() {
        assert_eq!(base64_file_to_bytes_by_line("challenge20.txt")[0], base64_to_bytes("SSdtIHJhdGVkICJSIi4uLnRoaXMgaXMgYSB3YXJuaW5nLCB5YSBiZXR0ZXIgdm9pZCAvIFBvZXRzIGFyZSBwYXJhbm9pZCwgREoncyBELXN0cm95ZWQ="))
    }

    #[test]
    #[should_panic(expected="File not found - terminating.")]
    fn test_base64_file_to_bytes_by_line_bad_file() {
        base64_file_to_bytes_by_line("nonexistentfile.txt");
    }

    #[test]
    fn test_base64_file_to_bytes_as_single() {
        let bytes = base64_file_to_bytes_as_single("challenge10.txt");
        assert_eq!(&bytes[0..10], &vec![0x09, 0x12, 0x30, 0xaa, 0xde, 0x3e, 0xb3, 0x30, 0xdb, 0xaa][0..10]);
    }

    #[test]
    #[should_panic(expected="File not found - terminating.")]
    fn test_base64_file_to_bytes_as_single_bad_file() {
        base64_file_to_bytes_as_single("nonexistentfile.txt");
    }
}