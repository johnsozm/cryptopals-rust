use crate::converter::{hex_to_bytes, bytes_to_hex};
use crate::xor::xor_bytes;

fn challenge2() -> String {
    let b1 = hex_to_bytes("1c0111001f010100061a024b53535009181c");
    let b2 = hex_to_bytes("686974207468652062756c6c277320657965");
    let xor = xor_bytes(&b1, &b2);
    return bytes_to_hex(&xor);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_solution() {
        assert_eq!(challenge2(), "746865206b696420646f6e277420706c6179");
    }
}