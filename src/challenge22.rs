use crate::mt19937::MT19937;
use rand::random;
use std::time::{SystemTime, UNIX_EPOCH};

///Gets simulated past timestamp
fn get_ts() -> u32 {
    let time = SystemTime::now().duration_since(UNIX_EPOCH);
    let timestamp = time.unwrap().as_millis() as u32;
    let simulated_duration: u32 = random();
    return timestamp - (simulated_duration % 1000) + 41;
}

fn challenge22(output: u32) -> u32 {
    let time = SystemTime::now().duration_since(UNIX_EPOCH);
    let mut ts = time.unwrap().as_millis() as u32;

    loop {
        let mut mt = MT19937::from_seed(ts);
        if mt.extract_number() == output {
            return ts;
        }
        ts -= 1;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_solution() {
        let past_ts = get_ts();
        let mut mt = MT19937::from_seed(past_ts);
        assert_eq!(challenge22(mt.extract_number()), past_ts);
    }
}