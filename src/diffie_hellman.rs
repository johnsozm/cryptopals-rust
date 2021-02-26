use crate::bignum::BigNum;
use rand::random;

lazy_static! {
    static ref DEFAULT_P: BigNum = BigNum::from(&vec![0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xc9, 0x0f, 0xda, 0xa2, 0x21, 0x68, 0xc2, 0x34, 0xc4, 0xc6, 0x62, 0x8b, 0x80, 0xdc, 0x1c, 0xd1, 0x29, 0x02, 0x4e, 0x08, 0x8a, 0x67, 0xcc, 0x74, 0x02, 0x0b, 0xbe, 0xa6, 0x3b, 0x13, 0x9b, 0x22, 0x51, 0x4a, 0x08, 0x79, 0x8e, 0x34, 0x04, 0xdd, 0xef, 0x95, 0x19, 0xb3, 0xcd, 0x3a, 0x43, 0x1b, 0x30, 0x2b, 0x0a, 0x6d, 0xf2, 0x5f, 0x14, 0x37, 0x4f, 0xe1, 0x35, 0x6d, 0x6d, 0x51, 0xc2, 0x45, 0xe4, 0x85, 0xb5, 0x76, 0x62, 0x5e, 0x7e, 0xc6, 0xf4, 0x4c, 0x42, 0xe9, 0xa6, 0x37, 0xed, 0x6b, 0x0b, 0xff, 0x5c, 0xb6, 0xf4, 0x06, 0xb7, 0xed, 0xee, 0x38, 0x6b, 0xfb, 0x5a, 0x89, 0x9f, 0xa5, 0xae, 0x9f, 0x24, 0x11, 0x7c, 0x4b, 0x1f, 0xe6, 0x49, 0x28, 0x66, 0x51, 0xec, 0xe4, 0x5b, 0x3d, 0xc2, 0x00, 0x7c, 0xb8, 0xa1, 0x63, 0xbf, 0x05, 0x98, 0xda, 0x48, 0x36, 0x1c, 0x55, 0xd3, 0x9a, 0x69, 0x16, 0x3f, 0xa8, 0xfd, 0x24, 0xcf, 0x5f, 0x83, 0x65, 0x5d, 0x23, 0xdc, 0xa3, 0xad, 0x96, 0x1c, 0x62, 0xf3, 0x56, 0x20, 0x85, 0x52, 0xbb, 0x9e, 0xd5, 0x29, 0x07, 0x70, 0x96, 0x96, 0x6d, 0x67, 0x0c, 0x35, 0x4e, 0x4a, 0xbc, 0x98, 0x04, 0xf1, 0x74, 0x6c, 0x08, 0xca, 0x23, 0x73, 0x27, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff]);
    static ref DEFAULT_G: BigNum = BigNum::from(2);
}

pub struct DiffieHellman {
    pub p: BigNum,
    pub g: BigNum,
    pub public_key: BigNum,
    private_key: BigNum,
    s: BigNum
}

impl DiffieHellman {
    ///Generates a new Diffie-Hellman struct with a random keypair and default parameters
    pub fn new() -> DiffieHellman {
        let mut ret = DiffieHellman {
            p: DEFAULT_P.clone(),
            g: DEFAULT_G.clone(),
            public_key: BigNum::from(0),
            private_key: BigNum::from(0),
            s: BigNum::from(0)
        };

        ret.generate_keys();

        return ret;
    }

    ///Generates a new Diffie-Hellman struct with a random keypair and the given parameters
    pub fn new_from_params(p: &BigNum, g: &BigNum) -> DiffieHellman {
        let mut ret = DiffieHellman {
            p: p.clone(),
            g: g.clone(),
            public_key: BigNum::from(0),
            private_key: BigNum::from(0),
            s: BigNum::from(0)
        };

        ret.generate_keys();

        return ret;
    }

    ///Generates a random private/public keypair
    fn generate_keys(&mut self) {
        let mut bytes: Vec<u8> = vec![];
        let target_len = self.p.len_bytes() + 1;

        for _i in 0..target_len {
            bytes.push(random());
        }

        self.private_key = &BigNum::from(&bytes) % &self.p;
        self.public_key = self.g.modular_exponent(&self.private_key, &self.p);
    }

    pub fn exchange_keys(&mut self, other: &mut DiffieHellman) {
        if self.p != other.p || self.g != other.g {
            panic!("Tried to perform a Diffie-Hellman exchange with incompatible parameters");
        }

        self.s = other.public_key.modular_exponent(&self.private_key, &self.p);
        other.s = self.public_key.modular_exponent(&other.private_key, &self.p);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new() {
        let zero = BigNum::from(0);
        let dh = DiffieHellman::new();

        assert_eq!(dh.p, *DEFAULT_P);
        assert_eq!(dh.g, *DEFAULT_G);
        assert_ne!(dh.private_key, zero);
        assert_ne!(dh.public_key, zero);
    }

    #[test]
    fn test_new_from_params() {
        let zero = BigNum::from(0);
        let test_p = BigNum::from(8675309);
        let test_g = BigNum::from(2);
        let dh = DiffieHellman::new_from_params(&test_p, &test_g);

        assert_eq!(dh.p, test_p);
        assert_eq!(dh.g, test_g);
        assert_ne!(dh.private_key, zero);
        assert_ne!(dh.public_key, zero);
    }

    #[test]
    fn test_key_exchange() {
        let mut dh1 = DiffieHellman::new();
        let mut dh2 = DiffieHellman::new();

        dh1.exchange_keys(&mut dh2);

        assert_eq!(dh1.s, dh2.s);
    }

    #[test]
    #[should_panic(expected="Tried to perform a Diffie-Hellman exchange with incompatible parameters")]
    fn test_key_exchange_mismatch_params() {
        let test_p = BigNum::from(8675309);
        let test_g = BigNum::from(2);
        let mut dh1 = DiffieHellman::new_from_params(&test_p, &test_g);
        let mut dh2 = DiffieHellman::new();

        dh1.exchange_keys(&mut dh2);
    }
}