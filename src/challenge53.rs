use rand::random;
use crate::hash::digest_bad_hash_16_from_state;

lazy_static! {
    static ref MESSAGE: Vec<u8> = {
        let mut m: Vec<u8> = vec![];
        for _i in 0..16384 { //Generate message of 2^10 16-byte blocks
            m.push(random());
        }
        m
    };
}

///Finds a collision between a message of 1 block and a message of length blocks
fn find_single_block_collision(length: usize, initial_state: &Vec<u8>) -> (Vec<u8>, Vec<u8>, Vec<u8>) {
    //Initialize random block of specified length
    let mut block1 = vec![];
    for _i in 0..length {
        block1.push(random());
    }
    let target_hash = digest_bad_hash_16_from_state(&block1, initial_state);

    //Generate random single blocks until we find a collision
    let mut block2 = vec![0; 16];
    while digest_bad_hash_16_from_state(&block2, initial_state) != target_hash {
        block2.clear();
        for _i in 0..16 {
            block2.push(random());
        }
    }

    return (target_hash, block1, block2);
}

fn challenge53() -> Vec<u8> {
    //Generate expandable message segments
    let mut long_segments = vec![];
    let mut short_segments = vec![];
    let mut state = vec![0xbe, 0xef];

    for k in (1..=10).rev() {
        let length = 16 * ((1 << (k-1)) + 1);
        let (new_state, m1, m2) = find_single_block_collision(length, &state);
        long_segments.push(m1);
        short_segments.push(m2);
        state = new_state;
    }

    let final_state = state.clone();

    //Generate list of intermediate hash states for the target message
    let mut message_states = vec![];
    state = vec![0xbe, 0xef];
    for i in 0..MESSAGE.len()/16 {
        state = digest_bad_hash_16_from_state(&MESSAGE[16*i..16*(i+1)].to_vec(), &state);
        message_states.push(u16::from_be_bytes([state[0], state[1]]));
    }

    //Generate bridge block
    let mut bridge_block = vec![0; 16];
    let mut message_index= 0;
    while message_index == 0 {
        bridge_block.clear();
        for _i in 0..16 {
            bridge_block.push(random());
        }
        let bridge_hash_bytes = digest_bad_hash_16_from_state(&bridge_block, &final_state);
        let bridge_hash = u16::from_be_bytes([bridge_hash_bytes[0], bridge_hash_bytes[1]]);

        for i in 11..message_states.len() {
            if bridge_hash == message_states[i] {
                message_index = i;
                break;
            }
        }
    }

    //Generate expandable message of correct length
    let mut forgery = vec![];
    let mut remaining_length = message_index;
    for i in 0..long_segments.len() {
        let segment_length = long_segments[i].len() / 16;
        let remaining_segments = long_segments.len() - i - 1;
        if remaining_length > segment_length && remaining_length - segment_length >= remaining_segments {
            remaining_length -= long_segments[i].len() / 16;
            forgery.append(&mut long_segments[i]);
        }
        else {
            remaining_length -= 1;
            forgery.append(&mut short_segments[i]);
        }
    }

    //Return expandable message || bridge block || tail of message
    forgery.append(&mut bridge_block);
    forgery.append(&mut MESSAGE[(message_index + 1)*16..].to_vec());

    return forgery;
}

#[cfg(test)]
mod tests {
    use crate::hash::Hash;
    use super::*;

    #[test]
    fn test_solution() {
        let forgery = challenge53();
        let hash = Hash::BAD16;
        assert_eq!(forgery.len(), MESSAGE.len());
        assert_eq!(hash.digest(&forgery), hash.digest(&MESSAGE));
    }
}