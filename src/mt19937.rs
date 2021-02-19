///Mersenne twister parameters (for 32-bit word)
const W: u32 = 32;
const N: usize = 624;
const M: usize = 397;
const R: u32 = 31;
const A: u32 = 0x9908B0DF;
const U: u32 = 11;
const D: u32 = 0xFFFFFFFF;
const S: u32 = 7;
const B: u32 = 0x9D2C5680;
const T: u32 = 15;
const C: u32 = 0xEFC60000;
const L: u32 = 18;
const F: u32 = 1812433253;
const LOWER_MASK: u32 = (1 << R) - 1;
const UPPER_MASK: u32 = !LOWER_MASK;

pub struct MT19937 {
    state: [u32;N],
    index: usize
}

impl MT19937 {
    ///Constructs a new generator from the given seed
    pub fn from_seed(seed: u32) -> MT19937 {
        let mut ret = MT19937 {
            state: [0; N],
            index: N
        };

        ret.state[0] = seed;
        for i in 1..N-1 {
            ret.state[i] = F.overflowing_mul(ret.state[i-1] ^ (ret.state[i-1] >> (W-2))).0.overflowing_add(i as u32).0;
        }
        return ret;
    }

    ///Constructs a new generator with the given internal state and index
    pub fn from_state(state: [u32; N], index: usize) -> MT19937 {
        return MT19937 {
            state,
            index
        };
    }

    ///Gets the next pseudorandom number from the generator
    ///Will panic if generator was initialized with a bad index.
    pub fn extract_number(&mut self) -> u32 {
        if self.index == N {
            self.twist();
        }

        let mut y = self.state[self.index];
        y = y ^ ((y >> U) & D);
        y = y ^ ((y.overflowing_shl(S)).0 & B);
        y = y ^ ((y.overflowing_shl(T)).0 & C);
        y = y ^ (y >> L);

        self.index += 1;
        return y;
    }

    ///Implements the twist operation
    fn twist(&mut self) {
        for i in 0..N-1 {
            let x = (self.state[i] & UPPER_MASK) + (self.state[i+1] & LOWER_MASK);
            let mut x_a = x >> 1;
            if x % 2 != 0 {
                x_a = x_a ^ A;
            }
            self.state[i] = self.state[(i + M) % N] ^ x_a;
        }

        self.index = 0;
    }
}

///Untempers an MT19937 output value to determine the internal state that generated it
pub fn untemper(output: u32) -> u32 {
    //Undo y = y ^ (y >> L)
    let y3 = output ^ (output >> L);

    //Undo y = y ^ ((y << T) & C)
    let y2 = y3 ^ (y3.overflowing_shl(T).0 & C);

    //Undo y = y ^ ((y << S) & B)
    let mut y1 = y2 ^ (y2.overflowing_shl(S).0 & B);
    y1 = y1 ^ (y1.overflowing_shl(2*S).0 & 0x94284000 as u32);
    y1 = y1 ^ (y1.overflowing_shl(4*S).0 & 0x10000000 as u32);

    //Undo y = y ^ ((y >> U) & D)
    let mut y = y1 ^ ((y1 >> U) & D);
    y = y ^ ((y >> 2*U) & D);

    return y;
}

///Encrypts plaintext using a twister instance as a key stream.
pub fn encrypt_mt19937(plaintext: &Vec<u8>, key: u16) -> Vec<u8> {
    let mut ciphertext = plaintext.clone();
    let mut twister = MT19937::from_seed(key as u32);
    for i in 0..plaintext.len() {
        ciphertext[i] ^= twister.extract_number() as u8;
    }

    return ciphertext;
}

///Decrypts ciphertext using a twister instance as a key stream.
pub fn decrypt_mt19937(ciphertext: &Vec<u8>, key: u16) -> Vec<u8> {
    let mut plaintext = ciphertext.clone();
    let mut twister = MT19937::from_seed(key as u32);
    for i in 0..plaintext.len() {
        plaintext[i] ^= twister.extract_number() as u8;
    }

    return plaintext;
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::random;
    use crate::converter::ascii_to_bytes;

    #[test]
    fn test_generation() {
        let mut mt = MT19937::from_seed(5489);
        assert_eq!(mt.extract_number(), 0xD091BB5C);
        assert_eq!(mt.extract_number(), 0x22AE9EF6);
        assert_eq!(mt.extract_number(), 0xE7E1FAEE);
        assert_eq!(mt.extract_number(), 0xD5C31F79);
        assert_eq!(mt.extract_number(), 0x2082352C);
        assert_eq!(mt.extract_number(), 0xF807B7DF);
        assert_eq!(mt.extract_number(), 0xE9D30005);
        assert_eq!(mt.extract_number(), 0x3895AFE1);
        assert_eq!(mt.extract_number(), 0xA1E24BBA);
        assert_eq!(mt.extract_number(), 0x4EE4092B);
    }

    #[test]
    fn test_untemper() {
        //Test with a series of random internal state values
        for _i in 0..100 {
            let state: u32 = random();
            let mut y: u32 = state;
            y = y ^ ((y >> U) & D);
            y = y ^ ((y.overflowing_shl(S)).0 & B);
            y = y ^ ((y.overflowing_shl(T)).0 & C);
            y = y ^ (y >> L);
            assert_eq!(untemper(y), state);
        }
    }

    #[test]
    fn test_encrypt_decrypt() {
        let message = ascii_to_bytes("Yahoo! Test message!");
        let ciphertext = encrypt_mt19937(&message, 12097);
        let plaintext = decrypt_mt19937(&ciphertext, 12097);
        assert_eq!(plaintext, message);
    }
}