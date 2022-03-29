use std::collections::HashMap;
use rand::random;
use crate::hash::digest_bad_hash_16_from_state;

lazy_static! {
    static ref MESSAGE: Vec<u8> = {
        let mut m: Vec<u8> = vec![];
        for _i in 0..1048576 { //Generate message of 2^16 16-byte blocks
            m.push(random());
        }
        m
    };
}

///Finds a collision between a message of 16 bytes and a message of length bytes
fn find_single_block_collision(length: usize, initial_state: &Vec<u8>) -> (Vec<u8>, Vec<u8>, Vec<u8>) {
    //Create random message of specified length - 1 block
    let mut block1 = vec![0; length-16];
    for i in 0..length-16 {
        block1[i] = random();
    }
    let final_state = digest_bad_hash_16_from_state(&block1, initial_state);

    let mut block1_final = vec![0; 16];
    let mut block2 = vec![0; 16];
    let mut hashes1: HashMap<u16, Vec<u8>> = HashMap::new();
    let mut hashes2: HashMap<u16, Vec<u8>> = HashMap::new();

    //Randomly generate block1 extensions and block2 until we find a collision, then return
    loop {
        let hash1 = digest_bad_hash_16_from_state(&block1_final, &final_state);
        let hash1_as_int = u16::from_be_bytes([hash1[0], hash1[1]]);
        if hashes2.contains_key(&hash1_as_int) {
            block1.append(&mut block1_final);
            return (hash1, block1, hashes2.get(&hash1_as_int).unwrap().clone());
        }
        else {
            hashes1.insert(hash1_as_int, block1_final.clone());
        }

        let hash2 = digest_bad_hash_16_from_state(&block2, initial_state);
        let hash2_as_int = u16::from_be_bytes([hash2[0], hash2[1]]);
        if hashes1.contains_key(&hash2_as_int) {
            block1.append(&mut hashes1.get(&hash2_as_int).unwrap().clone());
            return (hash2, block1, block2);
        }
        else {
            hashes2.insert(hash2_as_int, block2.clone());
        }

        for i in 0..16 {
            block1_final[i] = random();
            block2[i] = random();
        }
    }
}

fn challenge53() -> Vec<u8> {
    //Generate expandable message segments
    let mut long_segments = vec![];
    let mut short_segments = vec![];
    let mut state = vec![0xbe, 0xef];
    let mut message_exponent = 0;
    let mut predicted_len = 16;

    while predicted_len < MESSAGE.len() {
        message_exponent += 1;
        predicted_len *= 2;
    }

    for k in (1..=message_exponent).rev() {
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
        for i in 0..16 {
            bridge_block[i] = random();
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
        if (remaining_length > segment_length && remaining_length - segment_length >= remaining_segments)
            || (remaining_length == 2 && segment_length == 2){
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