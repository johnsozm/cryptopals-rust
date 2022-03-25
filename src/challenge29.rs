use crate::mac::{MAC, create_prefix_mac, verify_prefix_max};
use crate::converter::{ascii_to_bytes, bytes_to_ascii};
use rand::random;
use crate::hash::{Hash, digest_sha1_from_state};

lazy_static! {
    static ref KEY: Vec<u8> = {
        let len: usize = random();
        let mut k: Vec<u8> = vec![];
        for _i in 0..(len % 20) + 5 {
            k.push(random());
        }
        k
    };
}

///Generates original secret-prefix MAC message
fn generate_original_mac() -> MAC {
    let message = ascii_to_bytes("comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon");
    return create_prefix_mac(&message, &KEY, Hash::SHA1)
}

///Checks if the given token has a valid MAC and contains ";admin=true;"
fn is_admin(token: &MAC) -> bool {
    let ascii = bytes_to_ascii(&token.message);
    return ascii.contains(";admin=true;") && verify_prefix_max(&token, &KEY, Hash::SHA1);
}

fn challenge29() -> MAC {
    let original_mac = generate_original_mac();

    //Recreate hash state from signature
    let mut h = [0 as u32; 5];
    for i in 0..5 {
        h[i] += (original_mac.signature[4*i] as u32) << 24;
        h[i] += (original_mac.signature[4*i+1] as u32) << 16;
        h[i] += (original_mac.signature[4*i+2] as u32) << 8;
        h[i] += original_mac.signature[4*i+3] as u32;
    }

    let mut key_length: u64 = 8;

    //Generate extended message for possible key lengths until one works
    loop {
        let original_length = (original_mac.message.len() * 8) as u64 + key_length;
        let mut extended_message = original_mac.message.clone();
        let injection = ascii_to_bytes(";admin=true;");

        //Append "glue padding"
        extended_message.push(0x80);
        while (extended_message.len() + (key_length/8) as usize) % 64 != 56 {
            extended_message.push(0);
        }
        extended_message.append(&mut original_length.to_be_bytes().to_vec());

        //Append admin token
        extended_message.append(&mut injection.clone());

        let extended_length = (extended_message.len() * 8) as u64 + key_length;
        let extended_hash = digest_sha1_from_state(&injection, h, extended_length);

        let trial = MAC {
            message: extended_message,
            signature: extended_hash
        };

        if is_admin(&trial) {
            return trial;
        }

        key_length += 8;

        //Avoid infinite loops in case of an error
        if key_length > 1024 {
            break;
        }
    }

    //Default return in case of error
    return MAC {
        message: vec![],
        signature: vec![]
    };
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_solution() {
        assert!(is_admin(&challenge29()));
    }
}