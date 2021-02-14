use rand::random;
use crate::converter::base64_to_bytes;
use crate::aes::encrypt_ecb;
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

fn challenge14() -> String {
    //TODO: Determine block length, message length, and maximum prefix length
    //TODO: Determine encryption of some fixed block (eg, all 0xff)
    //TODO: Generate padding string that is 1 block of 0xff + just enough to fill max length prefix to a block
        //This ensures that we only get the 0xff block encrypted if prefix is at max, so we know where the test strings start
    //TODO: For each byte in the message:
        //TODO: As in challenge 12, but with the padding string prepended and only work on encryptions where we see the 0xff block

    return String::from("");
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