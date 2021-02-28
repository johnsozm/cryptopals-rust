//Most code is "dead" since it is only referenced by tests
#![allow(dead_code)]

//Required feature for Rocket
#![feature(decl_macro)]

//Allow for initializing random static variables
#[macro_use] extern crate lazy_static;

//Use Rocket & http crates for challenges that involve requests to an HTTP server.
#[macro_use] extern crate rocket;

/* Dependencies for timing attack code
use crate::converter::bytes_to_hex;
use std::fs::File;
use std::io::Read;
use crate::mac::create_hmac;
use crate::hash::Hash;
*/


//Alphabetic cipher module for other crypto challenges
mod alphabetic;

//Utility modules for the challenges to use
mod aes;
mod bignum;
mod converter;
mod diffie_hellman;
mod hash;
mod mac;
mod mt19937;
mod padding;
mod srp;
mod xor;

//Modules containing challenge solutions
mod challenge01;
mod challenge02;
mod challenge03;
mod challenge04;
mod challenge05;
mod challenge06;
mod challenge07;
mod challenge08;
mod challenge09;
mod challenge10;
mod challenge11;
mod challenge12;
mod challenge13;
mod challenge14;
//Challenge 15 was implementing the PKCS#7 pad/unpad routines - no additional code needed
mod challenge16;
mod challenge17;
mod challenge18;
//No code for challenge 19 - this was some limited ad-hoc fiddling
mod challenge20;
//Challenge 21 was implementing the mt19937 module - no additional code needed
mod challenge22;
mod challenge23;
mod challenge24;
mod challenge25;
mod challenge26;
mod challenge27;
//Challenge 28 was implementing secret-prefix MAC - no additional code needed
mod challenge29;
mod challenge30;
mod challenge31;
//Challenge 32 code is in challenge31 module (just made the tweaks in-place)
//Commented-out code in main routine should be used to run the timing channel attack
//since it takes so long the test suite gives up. (Approx runtime on my machine: 4hr)
//Challenge 33 was implementing the diffie_hellman module - no additional code needed
mod challenge34;
mod challenge35;
//Challenge 36 was implementing the srp module - no additional code needed

fn main() {
    /*let file = File::open("challenge10.txt");
    let mut contents: Vec<u8> = vec![];

    match file {
        Ok(mut f) => {
            f.read_to_end(&mut contents).unwrap();
        },
        Err(_) => ()
    };

    let mac = create_hmac(&contents, &challenge31::KEY, Hash::MD4);
    println!("Expected: {}", bytes_to_hex(&mac.signature));
    println!("Timing attack yielded: {}", bytes_to_hex(&challenge31::challenge31()));*/
}


