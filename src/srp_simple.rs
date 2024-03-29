use rand::random;
use std::collections::HashMap;
use gmp::mpz::Mpz;
use crate::converter::{ascii_to_bytes, bytes_to_hex, hex_to_bytes};
use crate::hash::Hash;
use crate::mac::{MAC, verify_hmac, create_hmac};

lazy_static! {
    pub static ref N: Mpz = Mpz::from_str_radix("ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff", 16).unwrap();
    pub static ref G: Mpz = Mpz::from(2);
    pub static ref K: Mpz = Mpz::from(3);
}

///Struct for holding login details for a single email address
struct SimpleSRPDetails {
    salt: u64,
    v: Mpz,
    k: Vec<u8>
}

///Struct for an SRP server, which can maintain many login details
pub struct SimpleSRPServer {
    logins: HashMap<String, SimpleSRPDetails>,
    public_key: Mpz,
    private_key: Mpz
}

///Struct for an SRP client, which can attempt to log into the server with its email + password
pub struct SimpleSRPClient {
    email: String,
    password: String,
    pub public_key: Mpz,
    private_key: Mpz
}

impl SimpleSRPServer {
    ///Generate a new server instance with no login details stored
    pub fn new() -> SimpleSRPServer {
        SimpleSRPServer {
            logins: HashMap::new(),
            public_key: Mpz::zero(),
            private_key: Mpz::zero()
        }
    }

    ///Stores login information for the given email and password
    pub fn add_login(&mut self, email: &str, password: &str) {
        //Calculate x = int(SHA256(salt|password))
        let salt: u64 = random();
        let mut x_h = salt.to_be_bytes().to_vec();
        x_h.append(&mut ascii_to_bytes(password));
        let x = Mpz::from(&Hash::SHA256.digest(&x_h)[0..32]);

        //Cast hash to int and calculate G^x mod N
        let v = G.powm(&x, &N);

        //Store login record
        self.logins.insert(email.to_string(), SimpleSRPDetails{salt, v, k: vec![]});
    }

    ///Generates a new random keypair for the server to use, given the value of V for this session
    fn generate_keypair(&mut self) {
        let mut bytes: Vec<u8> = vec![];
        let target_len = (N.bit_length() / 8) + 1; //Want at least 1 extra byte

        for _i in 0..target_len {
            bytes.push(random());
        }

        self.private_key = Mpz::from_str_radix(&bytes_to_hex(&bytes), 16).unwrap() % N.clone();
        self.public_key = G.powm(&self.private_key, &N);
    }

    ///Implements initial client request. Client sends (email, public key) and server responds (salt, public key)
    pub fn client_request(&mut self, email: &str, client_key: &Mpz) -> (u64, Mpz, u128) {
        let mut info: SimpleSRPDetails;
        match self.logins.get(email) {
            None => return (0, Mpz::zero(), 0), //If email is not found, return null values
            Some(i) => info = SimpleSRPDetails{salt: i.salt, v: i.v.clone(), k: vec![]}
        }
        let salt = info.salt;

        //Generate new keys and generate random u
        self.generate_keypair();
        let u: u128 = random();
        let u_high = (u >> 64) as u64;
        let u_low = u as u64;
        let u_mpz = (Mpz::from(u_high) << 64) + Mpz::from(u_low);

        //Calculate s = (A*v^u) ^ b mod N and derive key
        let base = client_key * info.v.powm(&u_mpz, &N);
        let s = base.powm(&self.private_key, &N);
        let s_bytes = hex_to_bytes(&s.to_str_radix(16));
        info.k = Hash::SHA256.digest(&s_bytes);

        //Update this email's info with derived key and respond to client
        self.logins.insert(email.to_string(), info);

        return (salt, self.public_key.clone(), u);
    }

    ///Validates client's login attempt
    pub fn validate_login(&self, email: &str, mac: &MAC) -> bool {
        return match self.logins.get(email) {
            None => false,
            Some(i) => {
                if mac.message != i.salt.to_be_bytes().to_vec() {
                    false
                }
                else {
                    verify_hmac(&mac, &i.k, Hash::SHA256)
                }
            }
        }
    }
}

impl SimpleSRPClient {
    ///Creates a new client instance which will attempt to log in with the given email and password
    pub fn new(email: &str, password: &str) -> SimpleSRPClient {
        let mut s = SimpleSRPClient {
            email: email.to_string(),
            password: password.to_string(),
            public_key: Mpz::zero(),
            private_key: Mpz::zero()
        };

        s.generate_keypair();
        return s;
    }

    ///Generates a new random keypair for the client to use
    fn generate_keypair(&mut self) {
        let mut bytes: Vec<u8> = vec![];
        let target_len = (N.bit_length() / 8) + 1; //Want at least 1 extra byte

        for _i in 0..target_len {
            bytes.push(random());
        }

        self.private_key = Mpz::from_str_radix(&bytes_to_hex(&bytes), 16).unwrap() % N.clone();
        self.public_key = Mpz::powm(&G, &self.private_key, &N);
    }

    ///Generates login token from server response
    pub fn generate_login(&self, salt: u64, server_key: &Mpz, u: u128) -> MAC {
        //Calculate u = int(SHA256(A|B))
        let mut combined_key = vec![];
        combined_key.append(&mut hex_to_bytes(&self.public_key.to_str_radix(16)));
        combined_key.append(&mut hex_to_bytes(&server_key.to_str_radix(16)));
        let u_high = (u >> 64) as u64;
        let u_low = u as u64;
        let u_mpz = (Mpz::from(u_high) << 64) + Mpz::from(u_low);

        //Calculate x = int(SHA256(salt|password))
        let mut x_h = salt.to_be_bytes().to_vec();
        x_h.append(&mut ascii_to_bytes(&self.password));
        let x = Mpz::from(&Hash::SHA256.digest(&x_h)[0..32]);

        //Calculate S = B ^ (a + u*x) mod N
        let s = server_key.powm(&(self.private_key.clone() + u_mpz*x), &N);

        //Calculate k = SHA256(s)
        let s_bytes = hex_to_bytes(&s.to_str_radix(16));
        let k = Hash::SHA256.digest(&s_bytes);

        //Generate HMAC with the generated key
        return create_hmac(&salt.to_be_bytes().to_vec(), &k, Hash::SHA256);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_simple_srp_exchange() {
        let email = "test@email.str";
        let password = "p@ssw0rd";
        let client = SimpleSRPClient::new(email, password);
        let mut server = SimpleSRPServer::new();
        server.add_login(email, password);

        let (salt, server_key, u) = server.client_request(email, &client.public_key);
        let mac = client.generate_login(salt, &server_key, u);
        assert!(server.validate_login(email, &mac));
    }
}



