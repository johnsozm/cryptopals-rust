use std::io::{BufRead, BufReader};
use std::fs::File;
use rand::random;
use crate::srp_simple::{SimpleSRPClient, G, N};
use gmp::mpz::Mpz;
use crate::converter::{hex_to_bytes, ascii_to_bytes};
use crate::hash::Hash;
use crate::mac::verify_hmac;

lazy_static! {
    //Select a random word from the wordlist to use for each run
    static ref PASSWORD: String = {
        let file = File::open("wordlist.txt").unwrap();
        let reader = BufReader::new(file);
        let mut words = vec![];

        for line in reader.lines() {
            words.push(line);
        }

        let sel: usize = random();
        match &words[sel % words.len()] {
            Ok(w) => w.to_string(),
            Err(_) => String::from("")
        }
    };
}

//Get client using selected password and a sample email (email is ignored so it doesn't matter)
fn generate_client() -> SimpleSRPClient {
    return SimpleSRPClient::new("example@email.com", &PASSWORD);
}

fn challenge38() -> String {
    let client = generate_client();

    //Use parameters salt=0, b=1 => B=G, u=1 => ux = x
    let salt: u64 = 0;
    let u: u128 = 1;
    let server_key = G.clone();
    let mac = client.generate_login(salt, &server_key, u);

    //Since b=1, A^b = A = B^a
    let constant_factor = client.public_key.clone();

    //For each word in the wordlist, attempt to generate matching S
    let file = File::open("wordlist.txt").unwrap();
    let reader = BufReader::new(file);

    for line in reader.lines() {
        let word = line.unwrap();
        let mut concat = salt.to_be_bytes().to_vec();
        concat.append(&mut ascii_to_bytes(&word));

        //Calculate k = SHA256((A*v^u)^b mod n) = SHA256(A^b * v mod N) = SHA256(A * g^x mod n)
        let x = Mpz::from(&Hash::SHA256.digest(&concat)[0..32]);
        let s = (&constant_factor * G.powm(&x, &N)).modulus(&N);
        let s_bytes = hex_to_bytes(&s.to_str_radix(16));
        let k = Hash::SHA256.digest(&s_bytes);

        if verify_hmac(&mac, &k, Hash::SHA256) {
            return word;
        }
    }

    //Default case if we don't find a working word
    return String::from("");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_solution() {
        assert_eq!(challenge38(), *PASSWORD);
    }
}