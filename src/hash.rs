///Enum of all implemented hash functions
pub enum Hash {
    SHA1
}

///Generic implementation which calls the appropriate digest method depending on the hash enum
impl Hash {
    pub fn digest(&self, message: &Vec<u8>) -> Vec<u8> {
        return match self {
            Hash::SHA1 => digest_sha1(&message),
        }
    }
}

///Generates the SHA-1 digest of a message
fn digest_sha1(message: &Vec<u8>) -> Vec<u8> {
    let mut h: [u32;5] = [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0];
    let ml: u64 = (message.len() * 8) as u64;

    //Pre-process message for digest
    let mut processed_message = message.clone();

    processed_message.push(0x80);
    while processed_message.len() % 64 != 56 {
        processed_message.push(0);
    }
    processed_message.append(&mut ml.to_be_bytes().to_vec());

    //Digest each 64-byte chunk
    for chunk in 0..processed_message.len() / 64 {

        //Break into words
        let mut w= [0 as u32; 80];
        for i in 0..16 {
            w[i] += (processed_message[64*chunk+4*i] as u32) << 24;
            w[i] += (processed_message[64*chunk+4* i +1] as u32) << 16;
            w[i] += (processed_message[64*chunk+4* i +2] as u32) << 8;
            w[i] += processed_message[64*chunk+4* i +3] as u32;
        }
        for i in 16..80 {
            w[i] = (w[i -3] ^ w[i -8] ^ w[i -14] ^ w[i -16]).rotate_left(1);
        }

        let mut a = h[0];
        let mut b = h[1];
        let mut c = h[2];
        let mut d = h[3];
        let mut e = h[4];
        let mut f: u32;
        let mut k: u32;

        for i in 0..80 {
            if i < 20{
                f = (b & c) | ((!b) & d);
                k = 0x5A827999;
            }
            else if i < 40 {
                f = b ^ c ^ d;
                k = 0x6ED9EBA1;
            }
            else if i < 60 {
                f = (b & c) | (b & d) | (c & d);
                k = 0x8F1BBCDC;
            }
            else {
                f = b ^ c ^ d;
                k = 0xCA62C1D6;
            }

            let tmp = (a.rotate_left(5)).overflowing_add(f).0.overflowing_add(e).0.overflowing_add(k).0.overflowing_add(w[i]).0;
            e = d;
            d = c;
            c = b.rotate_left(30);
            b = a;
            a = tmp;
        }

        h[0] = h[0].overflowing_add(a).0;
        h[1] = h[1].overflowing_add(b).0;
        h[2] = h[2].overflowing_add(c).0;
        h[3] = h[3].overflowing_add(d).0;
        h[4] = h[4].overflowing_add(e).0;
    }

    let mut hash = vec![];

    for i in 0..5 {
        hash.append(&mut h[i].to_be_bytes().to_vec());
    }

    return hash;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::converter::{ascii_to_bytes, bytes_to_hex};

    #[test]
    fn test_sha1() {
        assert_eq!(bytes_to_hex(&digest_sha1(&ascii_to_bytes("abc"))), "a9993e364706816aba3e25717850c26c9cd0d89d");
        assert_eq!(bytes_to_hex(&digest_sha1(&ascii_to_bytes(""))), "da39a3ee5e6b4b0d3255bfef95601890afd80709");
        assert_eq!(bytes_to_hex(&digest_sha1(&ascii_to_bytes("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"))), "84983e441c3bd26ebaae4aa1f95129e5e54670f1");
        assert_eq!(bytes_to_hex(&digest_sha1(&ascii_to_bytes("abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu"))), "a49b2446a02c645bf419f995b67091253a04a259");
        assert_eq!(bytes_to_hex(&digest_sha1(&ascii_to_bytes(&"a".repeat(1000000)))), "34aa973cd4c4daa4f61eeb2bdbad27316534016f");
    }
}