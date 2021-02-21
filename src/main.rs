//Most code is "dead" since it is only referenced by tests
#![allow(dead_code)]

//Allow for initializing random static variables
#[macro_use]
extern crate lazy_static;

//Alphabetic cipher module for other crypto challenges
mod alphabetic;

//Utility modules for the challenges to use
mod aes;
mod converter;
mod mt19937;
mod padding;
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

fn main() {
}


