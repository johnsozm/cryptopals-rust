use crate::aes::detect_ecb;
use crate::converter::base64_file_to_bytes_by_line;

fn challenge8() -> i32 {
    let messages = base64_file_to_bytes_by_line("challenge08.txt");

    let mut count = 0;
    for m in messages {
        if detect_ecb(&m) {
            count += 1;
        }
    }

    return count;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_solution() {
        assert_eq!(challenge8(), 1);
    }
}