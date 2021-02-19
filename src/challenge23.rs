use crate::mt19937::{MT19937, untemper};

fn challenge23(output: [u32;624]) -> MT19937 {
    let mut state = output.clone();
    for i in 0..624 {
        state[i] = untemper(state[i]);
    }

    return MT19937::from_state(state, 624);
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::random;

    #[test]
    fn test_solution() {
        let mut mt_target = MT19937::from_seed(random());
        let mut state = [0; 624];

        for i in 0..624 {
            state[i] = mt_target.extract_number();
        }

        let mut mt_test = challenge23(state);
        for _i in 0..624 {
            assert_eq!(mt_test.extract_number(), mt_target.extract_number());
        }
    }
}