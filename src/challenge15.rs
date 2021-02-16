use crate::padding::{PaddingError, pkcs7_unpad};

fn challenge15_good() -> Result<Vec<u8>, PaddingError> {
    let test_message: Vec<u8> = vec![12, 1, 15, 18, 19, 2, 2];
    return pkcs7_unpad(&test_message);
}

fn challenge15_bad() -> Result<Vec<u8>, PaddingError> {
    let test_message: Vec<u8> = vec![12, 1, 15, 18, 19, 4, 4];
    return pkcs7_unpad(&test_message);
}

#[cfg(test)]
mod tests {
    use crate::challenge15::{challenge15_good, challenge15_bad};

    fn test_solution() {
        let expected: Vec<u8> = vec![12, 1, 15, 18, 19];
        match challenge15_good() {
            Ok(x) => assert_eq!(x, expected),
            Err(_) => assert!(false)
        }
        match challenge15_bad() {
            Err(_) => assert!(true),
            Ok(_) => assert!(false)
        }
    }
}