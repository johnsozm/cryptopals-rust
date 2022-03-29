use crate::hash::{digest_bad_hash_16_from_state, Hash};
use rand::random;

#[derive(Clone)]
struct TreeNode {
    state_a: Vec<u8>,
    state_b: Vec<u8>,
    pad_block: Vec<u8>,
    final_state: Vec<u8>
}

///Generates a block which hashes to the same final state given two initial hash states
fn generate_collision(state_a: &Vec<u8>, state_b: &Vec<u8>) -> (Vec<u8>, Vec<u8>) {
    //Brute-force search for a collision
    let mut block = vec![0; 16];
    while digest_bad_hash_16_from_state(&block, &state_a) != digest_bad_hash_16_from_state(&block, &state_b) {
        for i in 0..16 {
            block[i] = random();
        }
    }

    return (digest_bad_hash_16_from_state(&block, &state_a), block);
}

///Generates a collision tree with the specified number of leaves (must be a power of 2),
///as well as the final predicted hash given the desired "prediction" length in blocks
fn generate_collision_tree(size: u32, message_length: usize) -> (Vec<Vec<TreeNode>>, Vec<u8>) {
    let mut tree = vec![];
    let mut layer = vec![];

    //Generate first layer of tree
    let mut hash = 0;
    while hash < size {
        let state_a = hash.to_be_bytes()[2..4].to_vec();
        let state_b = (hash + 1).to_be_bytes()[2..4].to_vec();
        let (final_state, pad_block) = generate_collision(&state_a, &state_b);
        let node = TreeNode {
            state_a,
            state_b,
            pad_block,
            final_state
        };
        layer.push(node);
        hash += 2;
    }

    tree.push(layer.clone());

    //Keep generating layers until we reach a single final state
    loop {
        layer.clear();
        let last_index = tree.len() - 1;
        if tree[last_index].len() == 1 {
            break;
        }

        //Collide each pair of states into a common state
        let mut i = 0;
        while i < tree[last_index].len() {
            let state_a = tree[last_index][i].final_state.clone();
            let state_b = tree[last_index][i+1].final_state.clone();
            let (final_state, pad_block) = generate_collision(&state_a, &state_b);
            let node = TreeNode {
                state_a,
                state_b,
                pad_block,
                final_state
            };
            layer.push(node);
            i += 2;
        }

        tree.push(layer.clone());
    }

    //Generate padding block - 8x 0x00 + 8 bytes of size information
    //Final message length: prediction length + 1 glue block + tree traversal
    let total_message_size = ((message_length + tree.len() + 1) * 16) as u64;
    let last_index = tree.len() - 1;
    let mut final_block = vec![0; 8];
    final_block.append(&mut total_message_size.to_be_bytes().to_vec());

    //Compute prediction hash and return along with tree
    let prediction_hash = digest_bad_hash_16_from_state(&final_block, &tree[last_index][0].final_state);
    return (tree, prediction_hash);
}

fn forge_prediction(actual_result: &Vec<u8>, tree: &Vec<Vec<TreeNode>>) -> Vec<u8> {
    let hash = Hash::BAD16;
    let result_hash = hash.digest(actual_result);

    //Generate a glue block that hashes the result's final state into a tree state
    let mut glue_block = vec![0; 16];
    let mut glue_hash ;
    loop {
        //Check if glue hash is small enough to be in the tree
        glue_hash = digest_bad_hash_16_from_state(&glue_block, &result_hash);
        let glue_int = u32::from_be_bytes([0, 0, glue_hash[0], glue_hash[1]]);
        if glue_int >> tree.len() == 0 {
            break;
        }

        //If not, generate another glue block and try again
        glue_block.clear();
        for _i in 0..16 {
            glue_block.push(random());
        }
    }

    //Initialize forgery to actual result || glue block
    let mut forgery = actual_result.clone();
    forgery.append(&mut glue_block);

    //Traverse tree to construct tail of message
    let mut state = glue_hash;
    for layer in 0..tree.len() {
        for i in 0..tree[layer].len() {
            if tree[layer][i].state_a == state || tree[layer][i].state_b == state {
                state = tree[layer][i].final_state.clone();
                forgery.append(&mut tree[layer][i].pad_block.clone());
                break;
            }
        }
    }

    let length = forgery.len();
    forgery.append(&mut vec![0; 8]);
    forgery.append(&mut length.to_be_bytes().to_vec());

    return forgery;
}

#[cfg(test)]
mod tests {
    use crate::hash::Hash;
    use super::*;

    #[test]
    fn test_solution() {
        //Generate tree and prediction hash
        let (tree, prediction_hash) = generate_collision_tree(64, 1000);

        //Generate a random 1000-block actual outcome
        let mut actual_result = vec![];
        for _i in 0..16000 {
            actual_result.push(random());
        }

        //Generate forged prediction
        let hash = Hash::BAD16;
        let forgery = forge_prediction(&actual_result, &tree);
        assert_eq!(hash.digest(&forgery), prediction_hash);
        assert_eq!(forgery[0..16000].to_vec(), actual_result);
    }
}