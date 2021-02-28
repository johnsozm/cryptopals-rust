use crate::mac::{MAC, create_hmac};
use crate::srp::{SRPServer, N};
use gmp::mpz::Mpz;
use crate::hash::Hash;

static EMAIL: &str = "test@email.com";
static PASSWORD: &str = "pass@word!";

pub fn challenge37_zero() -> (SRPServer, MAC) {
    let mut server = SRPServer::new();
    server.add_login(EMAIL, PASSWORD);

    //Send client request with A=0 to ensure server gets S=0
    let (salt, _) = server.client_request(EMAIL, &Mpz::zero());
    let key = Hash::SHA256.digest(&vec![0]);
    return (server, create_hmac(&salt.to_be_bytes().to_vec(), &key, Hash::SHA256));
}

pub fn challenge37_n() -> (SRPServer, MAC) {
    let mut server = SRPServer::new();
    server.add_login(EMAIL, PASSWORD);

    //Send client request with A=0 to ensure server gets S=0
    let (salt, _) = server.client_request(EMAIL, &N);
    let key = Hash::SHA256.digest(&vec![0]);
    return (server, create_hmac(&salt.to_be_bytes().to_vec(), &key, Hash::SHA256));
}

pub fn challenge37_n_squared() -> (SRPServer, MAC) {
    let mut server = SRPServer::new();
    server.add_login(EMAIL, PASSWORD);

    //Send client request with A=0 to ensure server gets S=0
    let (salt, _) = server.client_request(EMAIL, &(N.clone() * N.clone()));
    let key = Hash::SHA256.digest(&vec![0]);
    return (server, create_hmac(&salt.to_be_bytes().to_vec(), &key, Hash::SHA256));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_solution_zero() {
        let (server, mac) = challenge37_zero();
        assert!(server.validate_login(EMAIL, &mac));
    }

    #[test]
    fn test_solution_n() {
        let (server, mac) = challenge37_n();
        assert!(server.validate_login(EMAIL, &mac));
    }

    #[test]
    fn test_solution_n_squared() {
        let (server, mac) = challenge37_n_squared();
        assert!(server.validate_login(EMAIL, &mac));
    }
}