use crate::hash::{digest_bad_hash_16_from_state, Hash};
use rand::random;

///Finds a collision in the 16-bit hash function given an initial hash state
fn generate_collision(initial_state: &Vec<u8>) -> (Vec<u8>, Vec<u8>, Vec<u8>) {
    //Generate random block to collide to
    let mut block1 = vec![];
    for _i in 0..16 {
        block1.push(random());
    }

    let target_hash = digest_bad_hash_16_from_state(&block1, initial_state);
    let mut block2 = vec![0; 16];

    //Generate random blocks until we find collision with the first block, then return
    while digest_bad_hash_16_from_state(&block2, initial_state) != target_hash {
        block2.clear();
        for _i in 0..16 {
            block2.push(random());
        }
    }

    return (target_hash, block1, block2);
}

///Generates 2^len messages which collide in the 16-bit hash function
fn generate_colliding_messages(len: usize) -> Vec<Vec<u8>> {
    let mut state = vec![0xbe, 0xef];
    let mut collisions = vec![];

    //Generate len consecutive pairs of collisions
    while collisions.len() < len {
        let (next_state, b1, b2) = generate_collision(&state);
        collisions.push((b1, b2));
        state = next_state;
    }

    //Generate a list of all traversals of the collisions and return
    let mut messages = vec![vec![]];

    for i in 0..len {
        let (block1, block2) = collisions[i].clone();
        let mut new_messages = vec![];

        for m in messages {
            let mut m1 = m.clone();
            let mut m2 = m.clone();
            m1.append(&mut block1.clone());
            m2.append(&mut block2.clone());
            new_messages.push(m1);
            new_messages.push(m2);
        }

        messages = new_messages;
    }

    return messages;
}

fn challenge52() -> (Vec<u8>, Vec<u8>) {
    let hash = Hash::BAD24;
    let mut attempts = 0;

    loop {
        //Generate 2^12 messages which collide in the 16-bit hash function
        let candidates = generate_colliding_messages(12);
        attempts += 1;

        //Convert byte values to u32 values for quicker comparison
        let mut hash_values = vec![];
        for i in 0..candidates.len() {
            let v = hash.digest(&candidates[i]);
            let bytes = [0, v[0], v[1], v[2]];
            hash_values.push(u32::from_be_bytes(bytes));
        }

        //Check for collision - if found, return, else try again
        for i in 0..candidates.len() - 1 {
            for j in i+1..candidates.len() {
                if hash_values[i] == hash_values[j] {
                    println!("Found collision in 24-bit function after {} tries", attempts);
                    return (candidates[i].clone(), candidates[j].clone());
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hash::Hash;

    #[test]
    fn test_solution() {
        let hash1 = Hash::BAD16;
        let hash2 = Hash::BAD24;
        let (message1, message2) = challenge52();
        assert_eq!(hash1.digest(&message1), hash1.digest(&message2));
        assert_eq!(hash2.digest(&message1), hash2.digest(&message2));
    }
}