use crate::converter::{ascii_to_bytes, bytes_to_ascii};
use crate::padding::pkcs7_pad;

fn challenge9() -> String {
    let message = ascii_to_bytes("YELLOW SUBMARINE");
    let padded = pkcs7_pad(&message, 20);
    return bytes_to_ascii(&padded);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_solution() {
        assert_eq!(challenge9(), "YELLOW SUBMARINE\u{4}\u{4}\u{4}\u{4}");
    }
}