use crate::aes::encrypt_ecb;
use crate::converter::ascii_to_bytes;
use crate::xor::xor_repeating;

lazy_static! {
    static ref BAD_HASH_16_KEY: Vec<u8> = ascii_to_bytes("YELLOW SUBMARINE");
    static ref BAD_HASH_64_KEY: Vec<u8> = ascii_to_bytes("MURDEROUS PICKLE");
}

///Enum of all implemented hash functions
pub enum Hash {
    SHA1,
    SHA256,
    MD4,
    BAD16,
    BAD64
}

///Generic implementation which calls the appropriate digest method depending on the hash enum
impl Hash {
    pub fn digest(&self, message: &Vec<u8>) -> Vec<u8> {
        return match self {
            Hash::SHA1 => digest_sha1(&message),
            Hash::SHA256 => digest_sha256(&message),
            Hash::MD4 => digest_md4(&message),
            Hash::BAD16 => digest_bad_hash_16(&message),
            Hash::BAD64 => digest_bad_hash_64(&message)
        }
    }

    pub fn block_length(&self) -> usize {
        return match self {
            Hash::SHA1 => 64,
            Hash::SHA256 => 64,
            Hash::MD4 => 64,
            Hash::BAD16 => 16,
            Hash::BAD64 => 16
        }
    }

    pub fn hash_length(&self) -> usize {
        return match self {
            Hash::SHA1 => 20,
            Hash::SHA256 => 32,
            Hash::MD4 => 16,
            Hash::BAD16 => 2,
            Hash::BAD64 => 8
        }
    }
}

///Generates the SHA-1 digest of a message
fn digest_sha1(message: &Vec<u8>) -> Vec<u8> {
    //Call arbitrary-state function with the default SHA-1 initial state
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

        //Generate remaining words
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

        //Perform hashing steps for this block
        for i in 0..80 {
            if i < 20 {
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

    //Construct output digest
    let mut hash = vec![];
    for i in 0..5 {
        hash.append(&mut h[i].to_be_bytes().to_vec());
    }

    return hash;
}

///Generates the MD4 digest of a message
fn digest_md4(message: &Vec<u8>) -> Vec<u8> {
    //Call arbitrary-state function with the MD4 initial state
    return digest_md4_from_state(&message, [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476], 0);
}

///Generates the MD4 digest of a message using the given internal state
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

///Generates the SHA256 digest of a message
fn digest_sha256(message: &Vec<u8>) -> Vec<u8> {
    //Calls arbitrary-state function with the SHA-256 initial state
    return digest_sha256_from_state(message, [0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19], 0);
}

///Generates the SHA256 digest of a message from the given initial state
fn digest_sha256_from_state(message: &Vec<u8>, h_init: [u32;8], total_length: u64) -> Vec<u8> {
    //Initialize hash fields
    let mut h_arr = h_init.clone();
    let k: [u32;64] =
    [0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2];

    //Generate padded message for hashing
    let mut padded_message = message.clone();
    let ml: u64 = if total_length == 0 {(message.len() * 8) as u64} else {total_length};
    padded_message.push(0x80);
    while padded_message.len() % 64 != 56 {
        padded_message.push(0);
    }
    padded_message.append(&mut ml.to_be_bytes().to_vec());

    //Digest each 64-byte chunk
    for block in 0..padded_message.len() / 64 {
        //Initialize schedule array
        let mut w = [0 as u32;64];
        for i in 0..16 {
            w[i] += (padded_message[64*block+4*i] as u32) << 24;
            w[i] += (padded_message[64*block+4*i+1] as u32) << 16;
            w[i] += (padded_message[64*block+4*i+2] as u32) << 8;
            w[i] += padded_message[64*block+4*i+3] as u32;
        }
        for i in 16..64 {
            let s0: u32 = w[i-15].rotate_right(7) ^ w[i-15].rotate_right(18) ^ (w[i-15] >> 3);
            let s1: u32 = w[i-2].rotate_right(17) ^ w[i-2].rotate_right(19) ^ (w[i-2] >> 10);
            w[i] = w[i-16].overflowing_add(s0).0.overflowing_add(w[i-7]).0.overflowing_add(s1).0;
        }

        let mut a = h_arr[0];
        let mut b = h_arr[1];
        let mut c = h_arr[2];
        let mut d = h_arr[3];
        let mut e = h_arr[4];
        let mut f = h_arr[5];
        let mut g = h_arr[6];
        let mut h = h_arr[7];

        //Perform hash steps
        for i in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ ((!e) & g);
            let tmp1 = h.overflowing_add(s1).0.overflowing_add(ch).0.overflowing_add(k[i]).0.overflowing_add(w[i]).0;
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let tmp2 = s0.overflowing_add(maj).0;

            h = g;
            g = f;
            f = e;
            e = d.overflowing_add(tmp1).0;
            d = c;
            c = b;
            b = a;
            a = tmp1.overflowing_add(tmp2).0;
        }

        h_arr[0] = h_arr[0].overflowing_add(a).0;
        h_arr[1] = h_arr[1].overflowing_add(b).0;
        h_arr[2] = h_arr[2].overflowing_add(c).0;
        h_arr[3] = h_arr[3].overflowing_add(d).0;
        h_arr[4] = h_arr[4].overflowing_add(e).0;
        h_arr[5] = h_arr[5].overflowing_add(f).0;
        h_arr[6] = h_arr[6].overflowing_add(g).0;
        h_arr[7] = h_arr[7].overflowing_add(h).0;
    }

    let mut hash = vec![];
    for i in 0..8 {
        hash.append(&mut h_arr[i].to_be_bytes().to_vec());
    }

    return hash;
}

///Generates bad 16-bit hash from the given message
fn digest_bad_hash_16(message: &Vec<u8>) -> Vec<u8> {
    //Calls arbitrary-state function with default value
    return digest_bad_hash_16_from_state(message, &vec![0xbe, 0xef]);
}

///Generates bad 16-bit hash from the given message and initial state
fn digest_bad_hash_16_from_state(message: &Vec<u8>, state: &Vec<u8>) -> Vec<u8> {
    //Create message padded to a multiple of 16 bytes
    let mut padded_message = message.clone();
    while padded_message.len() % 16 != 0 {
        padded_message.push(0x55);
    }

    //Digest each 16-byte chunk and return final result
    let mut hash = state.clone();
    for i in 0..padded_message.len()/16 {
        let message_block = padded_message[16*i..16*(i+1)].to_vec();
        let xor = xor_repeating(&message_block, &hash);
        let encrypted = encrypt_ecb(&xor, &BAD_HASH_16_KEY);
        hash = encrypted[0..2].to_vec();
    }

    return hash;
}

///Generates bad 64-bit hash from the given message
fn digest_bad_hash_64(message: &Vec<u8>) -> Vec<u8> {
    //Calls arbitrary-state function with default value
    return digest_bad_hash_64_from_state(message, &vec![0xde, 0xad, 0xbe, 0xef, 0xfe, 0xed, 0xab, 0xed]);
}

///Generates bad 64-bit hash from the given message and initial state
fn digest_bad_hash_64_from_state(message: &Vec<u8>, state: &Vec<u8>) -> Vec<u8> {
    //Create message padded to a multiple of 16 bytes
    let mut padded_message = message.clone();
    while padded_message.len() % 16 != 0 {
        padded_message.push(0x55);
    }

    //Digest each 16-byte chunk and return final result
    let mut hash = state.clone();
    for i in 0..padded_message.len()/16 {
        let message_block = padded_message[16*i..16*(i+1)].to_vec();
        let xor = xor_repeating(&message_block, &hash);
        let encrypted = encrypt_ecb(&xor, &BAD_HASH_64_KEY);
        hash = encrypted[0..8].to_vec();
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

    #[test]
    fn test_sha256() {
        assert_eq!(bytes_to_hex(&digest_sha256(&ascii_to_bytes(""))).to_uppercase(), "E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855");
        assert_eq!(bytes_to_hex(&digest_sha256(&ascii_to_bytes("a"))).to_uppercase(), "CA978112CA1BBDCAFAC231B39A23DC4DA786EFF8147C4E72B9807785AFEE48BB");
        assert_eq!(bytes_to_hex(&digest_sha256(&ascii_to_bytes("abc"))).to_uppercase(), "BA7816BF8F01CFEA414140DE5DAE2223B00361A396177A9CB410FF61F20015AD");
        assert_eq!(bytes_to_hex(&digest_sha256(&ascii_to_bytes("message digest"))).to_uppercase(), "F7846F55CF23E14EEBEAB5B4E1550CAD5B509E3348FBC4EFA3A1413D393CB650");
        assert_eq!(bytes_to_hex(&digest_sha256(&ascii_to_bytes("abcdefghijklmnopqrstuvwxyz"))).to_uppercase(), "71C480DF93D6AE2F1EFAD1447C66C9525E316218CF51FC8D9ED832F2DAF18B73");
        assert_eq!(bytes_to_hex(&digest_sha256(&ascii_to_bytes("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"))).to_uppercase(), "248D6A61D20638B8E5C026930C3E6039A33CE45964FF2167F6ECEDD419DB06C1");
        assert_eq!(bytes_to_hex(&digest_sha256(&ascii_to_bytes("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"))).to_uppercase(), "DB4BFCBD4DA0CD85A60C3C37D3FBD8805C77F15FC6B1FDFE614EE0A7C8FDB4C0");
        assert_eq!(bytes_to_hex(&digest_sha256(&ascii_to_bytes("12345678901234567890123456789012345678901234567890123456789012345678901234567890"))).to_uppercase(), "F371BC4A311F2B009EEF952DD83CA80E2B60026C8E935592D0F9C308453C813E");
    }
}