use rand::random;
use crate::converter::{base64_to_bytes, ascii_to_bytes, bytes_to_ascii};
use crate::aes::{encrypt_ecb, detect_ecb};
use crate::padding::pkcs7_pad;

//Consistent encryption key for use by oracle
static KEY: [u8; 16] = [178, 172, 142, 53, 180, 30, 112, 114, 26, 148, 243, 132, 91, 229, 253, 113];

fn oracle(message: &Vec<u8>) -> Vec<u8> {
    let prefix_length: i32 = random();
    let mut plaintext= vec![];
    let mut secret = base64_to_bytes("Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK");

    for _i in 0..(prefix_length % 5) + 5 {
        plaintext.push(random());
    }

    plaintext.append(&mut message.clone());
    plaintext.append(&mut secret);
    return encrypt_ecb(&pkcs7_pad(&plaintext, 16), &KEY.to_vec());
}

pub fn challenge14() -> String {
    let mut string_length = 0;
    let mut max_null_length = 0;
    let mut block_length = 0;
    let mut added_length = 0;
    let mut message_length = 0;
    let mut max_prefix_length = 0;
    let mut post_prefix_index = 0;
    let mut known_block = vec![];

    //Find longest possible ciphertext length for null message
    for _i in 0..1000 {
        let test = oracle(&vec![]);
        if test.len() > max_null_length {
            max_null_length = test.len();
        }
    }

    //Find shortest possible string that generates an extra block to calculate total added length
    loop {
        string_length += 1;
        let mut found = false;
        let test_message = ascii_to_bytes(&"A".repeat(string_length));
        for _i in 0..1000 {
            let ciphertext_len = oracle(&test_message).len();
            if ciphertext_len > max_null_length {
                found = true;
                block_length = ciphertext_len - max_null_length;
                added_length = (ciphertext_len - block_length) - string_length;
                break;
            }
        }
        if found {
            break;
        }
    }

    string_length = block_length * 2 - 1;
    //Determine message length, max prefix length, and encryption of a block of 0xff
    loop {
        string_length += 1;
        let test_message = vec![0xff; string_length];
        let mut found = false;
        for _i in 0..1000 {
            let ciphertext = oracle(&test_message);

            //If we get a repeated block, we have a known plaintext/ciphertext pair & length info
            if detect_ecb(&ciphertext) {
                let mut block_index = 0;
                for block in 0..(ciphertext.len() / block_length) - 1 {
                    let b1 = ciphertext[block*block_length..(block+1)*block_length].to_vec();
                    let b2 = ciphertext[(block+1)*block_length..(block+2)*block_length].to_vec();
                    if b1 == b2 {
                        block_index = block;
                        known_block = b1;
                        break;
                    }
                }
                //Possible to get a false positive?
                if block_index == 0 {
                    continue;
                }
                max_prefix_length = block_length * block_index - (test_message.len() % block_length);
                post_prefix_index = (max_prefix_length / block_length) + (if max_prefix_length % block_length == 0 {0} else {1});
                message_length = added_length - max_prefix_length;
                found = true;
            }
        }
        if found {
            break;
        }
    }

    //Generate padding string that is 1 block of 0xff + just enough to fill max length prefix to a block
    //This ensures that we only get the 0xff block encrypted if prefix is at max, so we know where the test strings start
    let known_padding: Vec<u8> = vec![0xff; block_length * 2 - (max_prefix_length % block_length)];
    let mut message: Vec<u8> = vec![];
    let mut last_bytes: Vec<u8> = vec![];

    for _i in 0..block_length {
        last_bytes.push(0);
    }

    //Construct message 1 byte at a time
    for i in 0..message_length {
        //Construct trial block consisting of known_padding (0xff) + variable padding (0x00)
        let mut trial_block = known_padding.clone();
        for _j in 0..(block_length - (i % block_length) - 1) {
            trial_block.push(0);
        }

        //Repeatedly call oracle until the known ciphertext block appears
        let mut ciphertext;
        loop {
            ciphertext = oracle(&trial_block);
            if ciphertext[post_prefix_index * block_length..(post_prefix_index+1)*block_length].to_vec() == known_block {
                break;
            }
        }

        //Extract target ciphertext block
        let target_block_number = i / block_length + post_prefix_index + 1; //Message index + post-prefix index + 1 for 0xff block
        let target_block = ciphertext[target_block_number * block_length..(target_block_number + 1) * block_length].to_vec();

        //Construct trial block consisting of known text + unknown character
        for j in 0..block_length - 1 {
            last_bytes[j] = last_bytes[j + 1];
        }
        let mut trial_message = known_padding.clone();
        trial_message.append(&mut last_bytes.clone());
        let last_index = trial_message.len() - 1;

        //Find which final byte makes this work right
        for byte in 0..=255 {
            trial_message[last_index] = byte;
            //Repeatedly call oracle until the known ciphertext block appears
            loop {
                ciphertext = oracle(&trial_message);
                if ciphertext[post_prefix_index * block_length..(post_prefix_index+1)*block_length].to_vec() == known_block {
                    break;
                }
            }
            //Check if the next block matches the target block to see if we guessed the byte value
            if ciphertext[(post_prefix_index+1) * block_length..(post_prefix_index+2)*block_length].to_vec() == target_block {
                message.push(byte);
                last_bytes[block_length - 1] = byte;
                println!("Byte {} = {}", i, byte);
                break;
            }
        }
    }

    return bytes_to_ascii(&message);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::converter::bytes_to_ascii;

    #[test]
    fn test_solution() {
        let bytes = base64_to_bytes("Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK");
        let message = bytes_to_ascii(&bytes);

        assert_eq!(challenge14(), message);
    }
}