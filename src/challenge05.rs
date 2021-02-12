use crate::converter::{ascii_to_bytes, bytes_to_hex};
use crate::xor::xor_repeating;

fn challenge5() -> String {
    let plaintext = ascii_to_bytes("Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal");
    let key = ascii_to_bytes("ICE");
    let ciphertext = xor_repeating(&plaintext, &key);
    return bytes_to_hex(&ciphertext);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_solution() {
        assert_eq!(challenge5(), "b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f")
    }
}