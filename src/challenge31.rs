use std::thread::sleep;
use std::time::{Duration, SystemTime};
use std::fs::File;
use rand::random;
use crate::mac::create_hmac;
use crate::hash::Hash;
use crate::converter::{hex_to_bytes, bytes_to_hex};
use std::io::Read;
use rocket::http::Status;
use rocket::local::Client;

//Insecure comparison delay
static DELAY_MS: Duration = Duration::from_millis(5);

lazy_static! {
    pub static ref KEY: Vec<u8> = {
        let len: usize = random();
        let mut k: Vec<u8> = vec![];
        for _i in 0..(len % 20) + 5 {
            k.push(random());
        }
        k
    };
    static ref HASH: Vec<u8> = {
        let file = File::open("challenge10.txt");
        let mut contents: Vec<u8> = vec![];

        match file {
            Ok(mut f) => f.read_to_end(&mut contents).unwrap(),
            Err(_) => panic!("Could not open target file")
        };

        let mac = create_hmac(&contents, &KEY, Hash::MD4);
        mac.signature
    };
}

///Performs byte-by-byte comparison of a and b, delaying DELAY_MS after each byte.
fn insecure_compare(a: &Vec<u8>, b: &Vec<u8>) -> bool {
    if a.len() != b.len() {
        return false;
    }

    for i in 0..a.len(){
        if a[i] != b[i] {
            return false;
        }
        sleep(DELAY_MS);
    }
    return true;
}

///Checks if the file exists, and, if so, if the given signature is valid.
///Returns 200 for a valid signature, or 203 for invalid (thousands of 4xx/5xx codes cause Rocket to give up)
#[get("/check/<filename>/<signature>")]
fn check_signature(filename: String, signature: String) -> Status {
    if filename != "challenge10.txt" {
        return Status::NotFound;
    }
    let hash = hex_to_bytes(&signature);

    if insecure_compare(&hash, &HASH) {
        return Status::Ok;
    }

    return Status::Accepted;
}

pub fn challenge31() -> Vec<u8> {
    //Initialize webserver
    let target_base = "/check/challenge10.txt/";
    let mut hash: Vec<u8> = vec![0;Hash::MD4.hash_length()];
    let rocket = rocket::ignite().mount("/", routes![check_signature]);
    let client = Client::new(rocket).expect("valid rocket instance");

    //For each byte, time all possible values for the byte and assume longest time -> correct byte
    for i in 0..Hash::MD4.hash_length() {
        let mut max_time: u128 = 0;
        let mut max_byte: u8 = 0;

        for byte in 0..=255 as u8 {
            hash[i] = byte;
            let mut total_time: u128 = 0;

            for _attempt in 0..50 {
                //Generate test URI and initialize HTTP client
                let uri = format!("{}{}", target_base, bytes_to_hex(&hash));

                let start_time = SystemTime::now();

                let response = client.get(uri).dispatch();

                let end_time = SystemTime::now();

                //Exit immediately if we get 200 OK
                if response.status() == Status::Ok {
                    return hash;
                }

                let duration = end_time.duration_since(start_time);

                match duration {
                    Ok(d) => total_time += d.as_nanos(),
                    Err(_) => ()
                }
            }

            if total_time > max_time {
                max_time = total_time;
                max_byte = byte;
            }
        }

        hash[i] = max_byte;
    }

    return vec![];
}