use crate::rsa::{RSA, RSASignature};
use crate::converter::ascii_to_bytes;
use crate::hash::Hash;
use gmp::mpz::Mpz;

lazy_static! {
    static ref RSA_SERVER: RSA = RSA::new(1024);
}

fn solution42() -> RSASignature {
    let message = ascii_to_bytes("Hi mom");
    let hash = Hash::MD4.digest(&message);

    //Construct malicious padded block
    let mut block = vec![];
    //Initial padding: 00 01 [ff] 00
    block.push(0x00);
    block.push(0x01);
    block.push(0xff);
    block.push(0x00);

    //Append sequence header
    block.push(0x70); //Object is a constructed sequence
    block.push(0x15); //Total length is 21 bytes

    //Append hash specifier
    block.push(0x46); //Object is an object identifier
    block.push(0x01); //Length is 1 byte
    block.push(0x04); //Identifier for MD4 hash

    //Append hash bytes
    block.push(0x44); //Object is an octet string
    block.push(0x10); //Length is 16 bytes
    block.append(&mut hash.clone()); //Hash bytes

    block.append(&mut vec![0x55; 128 - block.len()]);

    //Take cube root of malicious block and use it as the signature
    let m = Mpz::from(&block[0..]);
    let c = m.root(3);

    return RSASignature {
        message,
        signature: c
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_solution() {
        assert!(RSA_SERVER.verify_signature(&solution42()));
    }
}