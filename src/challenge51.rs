use rand::random;
use crate::converter::ascii_to_bytes;
use deflate::deflate_bytes;
use crate::aes::encrypt_ctr;

///Returns the compressed length of a header containing secret key and the given message
fn compression_oracle(message: &Vec<u8>) -> usize {
    //Generate header bytes
    let mut header = String::from("");
    header += "POST / HTTP/1.1\n";
    header += "Host: hapless.com\n";
    header += "Cookie: sessionid=TmV2ZXIgcmV2ZWFsIHRoZSBXdS1UYW5nIFNlY3JldCE=\n";
    header += &format!("Content-Length: {}\n", message.len());
    let mut header_bytes = ascii_to_bytes(&header);
    header_bytes.append(&mut message.clone());

    //Encrypt header
    let mut key = vec![];
    let nonce: u64 = random();
    for _i in 0..16 {
        key.push(random());
    }
    let encrypted_header = encrypt_ctr(&header_bytes, &key, nonce);

    //Compress header and return length
    let compressed_header = deflate_bytes(&encrypted_header);
    return compressed_header.len();
}

fn challenge51() -> Vec<u8> {
    return vec![];
}

#[cfg(test)]
mod tests {
    use crate::converter::bytes_to_base64;
    use super::*;

    #[test]
    fn test_solution() {
        assert_eq!(bytes_to_base64(&challenge51()), "TmV2ZXIgcmV2ZWFsIHRoZSBXdS1UYW5nIFNlY3JldCE=");
    }
}