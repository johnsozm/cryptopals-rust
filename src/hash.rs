///Enum of all implemented hash functions
pub enum Hash {
    SHA1,
    MD4
}

///Generic implementation which calls the appropriate digest method depending on the hash enum
impl Hash {
    pub fn digest(&self, message: &Vec<u8>) -> Vec<u8> {
        return match self {
            Hash::SHA1 => digest_sha1(&message),
            Hash::MD4 => digest_md4(&message)
        }
    }
}

///Generates the SHA-1 digest of a message
fn digest_sha1(message: &Vec<u8>) -> Vec<u8> {
    digest_sha1_from_state(message, [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0], 0)
}

///Generates the SHA-1 digest of a message from some specific initial state
pub fn digest_sha1_from_state(message: &Vec<u8>, h_init: [u32;5], total_length: u64) -> Vec<u8> {
    let mut h: [u32;5] = h_init;
    let ml: u64 = if total_length == 0 {(message.len() * 8) as u64} else {total_length};

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
            w[i] += (processed_message[64*chunk+4*i+1] as u32) << 16;
            w[i] += (processed_message[64*chunk+4*i+2] as u32) << 8;
            w[i] += processed_message[64*chunk+4*i+3] as u32;
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

///Generates the MD4 digest of a message
fn digest_md4(message: &Vec<u8>) -> Vec<u8> {
    return digest_md4_from_state(&message, [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476], 0);
}

pub fn digest_md4_from_state(message: &Vec<u8>, init_buffer: [u32;4], total_length: u64) -> Vec<u8> {
    let mut padded_message = message.clone();
    let ml: u64 = if total_length == 0 {(message.len() * 8) as u64} else {total_length};

    //Pad message
    padded_message.push(0x80);
    while padded_message.len() % 64 != 56 {
        padded_message.push(0);
    }

    //Append little-endian length
    padded_message.append(&mut ml.to_le_bytes().to_vec());
    //Initialize buffers
    let mut a = init_buffer[0];
    let mut b = init_buffer[1];
    let mut c = init_buffer[2];
    let mut d = init_buffer[3];

    //Process message 16 32-bit words at a time
    for i in 0..padded_message.len() / 64 {
        let a_init = a;
        let b_init = b;
        let c_init = c;
        let d_init = d;

        let mut x = [0 as u32; 16];
        for j in 0..16 {
            x[j] += (padded_message[64*i+4*j+3] as u32) << 24;
            x[j] += (padded_message[64*i+4*j+2] as u32) << 16;
            x[j] += (padded_message[64*i+4*j+1] as u32) << 8;
            x[j] += padded_message[64*i+4*j] as u32;
        }

        //Round 1
        a = a.overflowing_add(x[0]).0.overflowing_add((b&c)|((!b)&d)).0.rotate_left(3);
        d = d.overflowing_add(x[1]).0.overflowing_add((a&b)|((!a)&c)).0.rotate_left(7);
        c = c.overflowing_add(x[2]).0.overflowing_add((d&a)|((!d)&b)).0.rotate_left(11);
        b = b.overflowing_add(x[3]).0.overflowing_add((c&d)|((!c)&a)).0.rotate_left(19);
        a = a.overflowing_add(x[4]).0.overflowing_add((b&c)|((!b)&d)).0.rotate_left(3);
        d = d.overflowing_add(x[5]).0.overflowing_add((a&b)|((!a)&c)).0.rotate_left(7);
        c = c.overflowing_add(x[6]).0.overflowing_add((d&a)|((!d)&b)).0.rotate_left(11);
        b = b.overflowing_add(x[7]).0.overflowing_add((c&d)|((!c)&a)).0.rotate_left(19);
        a = a.overflowing_add(x[8]).0.overflowing_add((b&c)|((!b)&d)).0.rotate_left(3);
        d = d.overflowing_add(x[9]).0.overflowing_add((a&b)|((!a)&c)).0.rotate_left(7);
        c = c.overflowing_add(x[10]).0.overflowing_add((d&a)|((!d)&b)).0.rotate_left(11);
        b = b.overflowing_add(x[11]).0.overflowing_add((c&d)|((!c)&a)).0.rotate_left(19);
        a = a.overflowing_add(x[12]).0.overflowing_add((b&c)|((!b)&d)).0.rotate_left(3);
        d = d.overflowing_add(x[13]).0.overflowing_add((a&b)|((!a)&c)).0.rotate_left(7);
        c = c.overflowing_add(x[14]).0.overflowing_add((d&a)|((!d)&b)).0.rotate_left(11);
        b = b.overflowing_add(x[15]).0.overflowing_add((c&d)|((!c)&a)).0.rotate_left(19);

        //Round 2
        a = a.overflowing_add(x[0]).0.overflowing_add(0x5a827999).0.overflowing_add((b&c)|(c&d)|(b&d)).0.rotate_left(3);
        d = d.overflowing_add(x[4]).0.overflowing_add(0x5a827999).0.overflowing_add((a&b)|(b&c)|(a&c)).0.rotate_left(5);
        c = c.overflowing_add(x[8]).0.overflowing_add(0x5a827999).0.overflowing_add((d&a)|(a&b)|(d&b)).0.rotate_left(9);
        b = b.overflowing_add(x[12]).0.overflowing_add(0x5a827999).0.overflowing_add((c&d)|(d&a)|(c&a)).0.rotate_left(13);
        a = a.overflowing_add(x[1]).0.overflowing_add(0x5a827999).0.overflowing_add((b&c)|(c&d)|(b&d)).0.rotate_left(3);
        d = d.overflowing_add(x[5]).0.overflowing_add(0x5a827999).0.overflowing_add((a&b)|(b&c)|(a&c)).0.rotate_left(5);
        c = c.overflowing_add(x[9]).0.overflowing_add(0x5a827999).0.overflowing_add((d&a)|(a&b)|(d&b)).0.rotate_left(9);
        b = b.overflowing_add(x[13]).0.overflowing_add(0x5a827999).0.overflowing_add((c&d)|(d&a)|(c&a)).0.rotate_left(13);
        a = a.overflowing_add(x[2]).0.overflowing_add(0x5a827999).0.overflowing_add((b&c)|(c&d)|(b&d)).0.rotate_left(3);
        d = d.overflowing_add(x[6]).0.overflowing_add(0x5a827999).0.overflowing_add((a&b)|(b&c)|(a&c)).0.rotate_left(5);
        c = c.overflowing_add(x[10]).0.overflowing_add(0x5a827999).0.overflowing_add((d&a)|(a&b)|(d&b)).0.rotate_left(9);
        b = b.overflowing_add(x[14]).0.overflowing_add(0x5a827999).0.overflowing_add((c&d)|(d&a)|(c&a)).0.rotate_left(13);
        a = a.overflowing_add(x[3]).0.overflowing_add(0x5a827999).0.overflowing_add((b&c)|(c&d)|(b&d)).0.rotate_left(3);
        d = d.overflowing_add(x[7]).0.overflowing_add(0x5a827999).0.overflowing_add((a&b)|(b&c)|(a&c)).0.rotate_left(5);
        c = c.overflowing_add(x[11]).0.overflowing_add(0x5a827999).0.overflowing_add((d&a)|(a&b)|(d&b)).0.rotate_left(9);
        b = b.overflowing_add(x[15]).0.overflowing_add(0x5a827999).0.overflowing_add((c&d)|(d&a)|(c&a)).0.rotate_left(13);

        //Round 3
        a = a.overflowing_add(x[0]).0.overflowing_add(0x6ed9eba1).0.overflowing_add(b^c^d).0.rotate_left(3);
        d = d.overflowing_add(x[8]).0.overflowing_add(0x6ed9eba1).0.overflowing_add(a^b^c).0.rotate_left(9);
        c = c.overflowing_add(x[4]).0.overflowing_add(0x6ed9eba1).0.overflowing_add(d^a^b).0.rotate_left(11);
        b = b.overflowing_add(x[12]).0.overflowing_add(0x6ed9eba1).0.overflowing_add(c^d^a).0.rotate_left(15);
        a = a.overflowing_add(x[2]).0.overflowing_add(0x6ed9eba1).0.overflowing_add(b^c^d).0.rotate_left(3);
        d = d.overflowing_add(x[10]).0.overflowing_add(0x6ed9eba1).0.overflowing_add(a^b^c).0.rotate_left(9);
        c = c.overflowing_add(x[6]).0.overflowing_add(0x6ed9eba1).0.overflowing_add(d^a^b).0.rotate_left(11);
        b = b.overflowing_add(x[14]).0.overflowing_add(0x6ed9eba1).0.overflowing_add(c^d^a).0.rotate_left(15);
        a = a.overflowing_add(x[1]).0.overflowing_add(0x6ed9eba1).0.overflowing_add(b^c^d).0.rotate_left(3);
        d = d.overflowing_add(x[9]).0.overflowing_add(0x6ed9eba1).0.overflowing_add(a^b^c).0.rotate_left(9);
        c = c.overflowing_add(x[5]).0.overflowing_add(0x6ed9eba1).0.overflowing_add(d^a^b).0.rotate_left(11);
        b = b.overflowing_add(x[13]).0.overflowing_add(0x6ed9eba1).0.overflowing_add(c^d^a).0.rotate_left(15);
        a = a.overflowing_add(x[3]).0.overflowing_add(0x6ed9eba1).0.overflowing_add(b^c^d).0.rotate_left(3);
        d = d.overflowing_add(x[11]).0.overflowing_add(0x6ed9eba1).0.overflowing_add(a^b^c).0.rotate_left(9);
        c = c.overflowing_add(x[7]).0.overflowing_add(0x6ed9eba1).0.overflowing_add(d^a^b).0.rotate_left(11);
        b = b.overflowing_add(x[15]).0.overflowing_add(0x6ed9eba1).0.overflowing_add(c^d^a).0.rotate_left(15);

        a = a.overflowing_add(a_init).0;
        b = b.overflowing_add(b_init).0;
        c = c.overflowing_add(c_init).0;
        d = d.overflowing_add(d_init).0;
    }

    //Construct output digest
    let mut hash = vec![];
    hash.append(&mut a.to_le_bytes().to_vec());
    hash.append(&mut b.to_le_bytes().to_vec());
    hash.append(&mut c.to_le_bytes().to_vec());
    hash.append(&mut d.to_le_bytes().to_vec());

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

    #[test]
    fn test_md4() {
        assert_eq!(bytes_to_hex(&digest_md4(&ascii_to_bytes(""))), "31d6cfe0d16ae931b73c59d7e0c089c0");
        assert_eq!(bytes_to_hex(&digest_md4(&ascii_to_bytes("a"))), "bde52cb31de33e46245e05fbdbd6fb24");
        assert_eq!(bytes_to_hex(&digest_md4(&ascii_to_bytes("abc"))), "a448017aaf21d8525fc10ae87aa6729d");
        assert_eq!(bytes_to_hex(&digest_md4(&ascii_to_bytes("message digest"))), "d9130a8164549fe818874806e1c7014b");
        assert_eq!(bytes_to_hex(&digest_md4(&ascii_to_bytes("abcdefghijklmnopqrstuvwxyz"))), "d79e1c308aa5bbcdeea8ed63df412da9");
        assert_eq!(bytes_to_hex(&digest_md4(&ascii_to_bytes("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"))), "43f8582f241db351ce627e153e7f0e4");
        assert_eq!(bytes_to_hex(&digest_md4(&ascii_to_bytes("12345678901234567890123456789012345678901234567890123456789012345678901234567890"))), "e33b4ddc9c38f2199c3e7b164fcc0536");
    }
}