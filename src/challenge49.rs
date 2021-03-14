use crate::mac::{MAC, create_cbc_mac, verify_cbc_mac};
use crate::converter::{ascii_to_bytes, bytes_to_ascii};
use rand::random;
use crate::xor::xor_bytes;
use crate::padding::pkcs7_pad;

lazy_static! {
    static ref KEY: Vec<u8> = {
        let mut k: Vec<u8> = vec![];
        for _i in 0..16 {
            k.push(random());
        }
        k
    };
    static ref IV: Vec<u8> = vec![0;16];
}

fn intercepted_mac() -> MAC {
    let message = ascii_to_bytes("from:12481632&tx_list=128374:1020.22;298566927;12.91");
    return create_cbc_mac(&message, &KEY, &IV);
}

fn sign_message(message: &Vec<u8>) -> MAC {
    let mut full_message = ascii_to_bytes("from:8675309&tx_list=");
    full_message.append(&mut message.clone());
    return create_cbc_mac(&full_message, &KEY, &IV);
}

fn verify_transfer(mac: &MAC) -> bool {
    let message = bytes_to_ascii(&mac.message);
    return message.starts_with("from:12481632&") && message.contains(";8675309:1000000.00") && verify_cbc_mac(mac, &KEY, &IV);
}

fn challenge49() -> MAC {
    //Initial work for attack
    let intercepted_mac = intercepted_mac();
    let extension = ascii_to_bytes(";8675309:1000000.00");
    let e_1 = extension[0..16].to_vec(); //Separate this 16-byte block out since we will need to do math on it
    let e_n = extension[16..].to_vec();

    //Sign a known message so we can use it as a base for forgery
    let mut tampered_message = ascii_to_bytes("Random message");
    let signed = sign_message(&tampered_message);

    //Append padding bytes to original message to make a full previous plaintext block AFTER HEADER IS ADDED
    let padding_length = 16 - (signed.message.len() % 16);
    tampered_message.append(&mut vec![padding_length as u8; padding_length]);

    //Generate first block of tampered extension as signature ^ intercepted signature ^ first block of plain extension
    //This ensures that the encryption of this block is equal to the encryption of intercepted signature ^ first block of plain extension
    let first_block = xor_bytes(&signed.signature, &xor_bytes(&intercepted_mac.signature, &e_1));
    tampered_message.append(&mut first_block.clone());
    //Append the rest of the message
    tampered_message.append(&mut e_n.clone());
    let tampered_mac = sign_message(&tampered_message);

    //Initialize forged message to intercepted value + padding
    let mut forged_message = pkcs7_pad(&intercepted_mac.message, 16);
    //Append length extension
    forged_message.append(&mut extension.clone());

    return MAC {
        message: forged_message,
        signature: tampered_mac.signature
    };
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_solution() {
        assert!(verify_transfer(&challenge49()));
    }
}