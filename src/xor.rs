//Xor's two equal-length byte strings together.
//Panics if the byte strings are not of equal length.
pub fn xor_bytes(byte1: Vec<u8>, byte2: Vec<u8>) -> Vec<u8> {
    if byte1.len() != byte2.len() {
        panic!("Byte strings must be of equal length!")
    }
    let it1 = byte1.iter();
    let it2 = byte2.iter();
    let zipped = it1.zip(it2);
    return zipped.map(|(x, y)| x ^ y).collect();
}
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_xor_bytes() {
        let b1: Vec<u8> = vec![0x1c, 0x01, 0x11];
        let b2: Vec<u8> = vec![0x68, 0x69, 0x74];
        let x: Vec<u8> = vec![0x74, 0x68, 0x65];
        assert_eq!(xor_bytes(b1, b2), x);
    }

    #[test]
    #[should_panic(expected="Byte strings must be of equal length!")]
    fn test_xor_bytes_mismatch() {
        let b1: Vec<u8> = vec![0x1c, 0x01, 0x11];
        let b2: Vec<u8> = vec![0x68, 0x69];
        xor_bytes(b1, b2);
    }
}