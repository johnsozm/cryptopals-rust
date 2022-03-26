use rand::random;
use crate::converter::ascii_to_bytes;
use deflate::deflate_bytes;
use crate::aes::encrypt_ctr;

///Returns the compressed length of a header containing secret key and the given message
fn compression_oracle(message: &Vec<u8>) -> usize {
    //Generate header bytes
    let header = format!("Host: hapless.com\nCookie: sessionid=TmV2ZXIgcmV2ZWFsIHRoZSBXdS1UYW5nIFNlY3JldCE=\nContent-Length: {}\n", message.len());
    let mut header_bytes = ascii_to_bytes(&header);
    header_bytes.append(&mut message.clone());

    //Compress header
    let compressed_header = deflate_bytes(&header_bytes);

    //Encrypt header and return length
    let mut key = vec![];
    let nonce: u64 = random();
    for _i in 0..16 {
        key.push(random());
    }
    let encrypted_header = encrypt_ctr(&compressed_header, &key, nonce);
    return encrypted_header.len();
}

fn challenge51() -> String {
    //Set of valid Base64 characters for testing
    let base64_string = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+/";
    let mut base64_chars = vec![];
    for c in base64_string.chars() {
        base64_chars.push(c);
    }

    let mut session_token = String::from("");
    let mut candidates = vec![String::from("")];
    let mut best_length ;

    //Construct session token based on compression oracle results
    while session_token.len() < 43 && candidates.len() < 4096 {
        //Reset best length for each pass
        best_length = usize::MAX;

        //Check all possible candidate + next character combinations with the compression oracle
        let mut new_candidates = vec![];
        for candidate in &candidates {
            //Construct base message
            let mut message = ascii_to_bytes(&format!("sessionid={}{}", session_token, candidate));
            message.push(0);
            let last_index = message.len() - 1;

            //Find shortest compression and log
            for next_digit in &base64_chars {
                message[last_index] = *next_digit as u8;
                let length = compression_oracle(&message);

                if length == best_length {
                    new_candidates.push(candidate.clone() + &next_digit.to_string());
                }
                if length < best_length {
                    best_length = length;
                    new_candidates = vec![candidate.clone() + &next_digit.to_string()];
                }
            }
        }

        candidates = new_candidates;

        //If we've narrowed down to one candidate, log it and clear the candidate list
        if candidates.len() == 1 {
            session_token += &candidates[0];
            candidates = vec![String::from("")];
        }
    }

    return session_token + "="; //Assume we know padding based on token size
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_solution() {
        assert_eq!(challenge51(), "TmV2ZXIgcmV2ZWFsIHRoZSBXdS1UYW5nIFNlY3JldCE=");
    }
}