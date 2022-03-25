use crate::aes::{decrypt_ecb, encrypt_ecb, detect_ecb};
use crate::converter::{bytes_to_ascii, ascii_to_bytes};
use crate::padding::{pkcs7_pad, pkcs7_unpad};
use rand::random;

lazy_static! {
    static ref KEY: Vec<u8> = {
        let mut k: Vec<u8> = vec![];
        for _i in 0..16 {
            k.push(random());
        }
        k
    };
}

///Checks if the given encrypted profile string has the admin flag
fn is_admin(profile: Vec<u8>) -> bool {
    let plaintext = pkcs7_unpad(&decrypt_ecb(&profile, &KEY));
    let ascii = bytes_to_ascii(&plaintext.unwrap());
    return ascii.contains("&role=admin");
}

///Generates encrypted profile for the given email
fn profile_for(email: &str) -> Vec<u8> {
    let escaped = email.replace("&", "").replace("=", "");
    let mut profile = String::from("email=");
    profile.push_str(&escaped);
    profile.push_str("&uid=10&role=user");
    let profile_bytes = pkcs7_pad(&ascii_to_bytes(&profile), 16);
    return encrypt_ecb(&profile_bytes, &KEY.to_vec());
}

fn challenge13() -> Vec<u8> {
    //Determine block length and total prefix+suffix length
    let base_length = profile_for("").len();
    let mut email_length = 0;
    let mut test_length = base_length;

    while test_length == base_length {
        email_length += 1;
        test_length = profile_for(&"A".repeat(email_length)).len();
    }

    let block_length = test_length - base_length;
    let added_length = base_length - email_length;
    let mut prefix_length = 0;

    //Keep extending email until we get 2 identical ciphertext blocks to determine prefix length
    loop {
        email_length += 1;
        let test = profile_for(&"A".repeat(email_length));
        if detect_ecb(&test) {
            for block_index in 0..(test.len() / block_length) - 1 {
                let base_index = block_index * block_length;
                let split_index = base_index + block_length;
                let final_index = split_index + block_length;

                let block1 = test[base_index..split_index].to_vec();
                let block2 = test[split_index..final_index].to_vec();
                if block1 == block2 {
                    prefix_length = block_length * (block_index - 1) + (block_length - (email_length % block_length));
                    break;
                }
            }
            break;
        }
    }

    //Generate profile which has a block containing "admin[pad to block length]"
    let mut attack_email = ascii_to_bytes(&"A".repeat(block_length - (prefix_length % block_length)));
    attack_email.append(&mut ascii_to_bytes(&"admin"));
    for _i in 0..block_length - 5 {
        attack_email.push((block_length - 5) as u8);
    }
    let admin_profile = profile_for(&bytes_to_ascii(&attack_email));

    //Generate profile 2 which has the final block "user[pad to block length]"
    let mut user_email = String::from("");
    if added_length % block_length < 4 {
        user_email.push_str(&"A".repeat(4 - (added_length % block_length)));
    }
    else {
        user_email.push_str(&"A".repeat((block_length + 4) - (added_length % block_length)));
    }

    //Replace last block of profile 2 with admin block of profile 1
    let mut attack_profile = profile_for(&user_email);
    let source_block = prefix_length / block_length + (if prefix_length % block_length == 0 {0} else {1});
    let target_block = (attack_profile.len() / block_length) - 1;

    for i in 0..block_length {
        attack_profile[target_block * block_length + i] = admin_profile[source_block * block_length + i];
    }

    return attack_profile;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_solution() {
        assert!(is_admin(challenge13()));
    }
}