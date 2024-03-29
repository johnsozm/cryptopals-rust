use rand::random;
use crate::challenge55::ConditionVariable::*;

enum ConditionVariable {
    CONST = 0,
    A = 1,
    B = 2,
    C = 3,
    D = 4
}

///MD4 helper functions
fn f(x: u32, y: u32, z: u32) -> u32 {(x&y)|((!x)&z)}
fn g(x: u32, y: u32, z: u32) -> u32 {(x&y)|(y&z)|(x&z)}
fn h(x: u32, y: u32, z: u32) -> u32 {x^y^z}
fn md4_add(base: u32, message: u32, offset: u32, function: u32, shift: u32) -> u32 {
    return base.overflowing_add(message).0.overflowing_add(offset).0.overflowing_add(function).0.rotate_left(shift);
}
fn md4_subtract(base: u32, offset: u32, function: u32, shift: u32) -> u32 {
    return base.rotate_right(shift).overflowing_sub(offset).0.overflowing_sub(function).0;
}

///Wang's conditions on the round 1 intermediate values
///Read each tuple as (variable1, step1, variable2, step2, bit)
static ROUND_1_CONDITIONS: [(ConditionVariable, usize, ConditionVariable, usize, u32); 95] = {[
    (A, 1, B, 0, 7),
    (D, 1, CONST, 0, 7),
    (D, 1, A, 1, 8),
    (D, 1, A, 1, 11),
    (C, 1, CONST, 1, 7),
    (C, 1, CONST, 1, 8),
    (C, 1, CONST, 0, 11),
    (C, 1, D, 1, 26),
    (B, 1, CONST, 1, 7),
    (B, 1, CONST, 0, 8),
    (B, 1, CONST, 0, 11),
    (B, 1, CONST, 0, 26),
    (A, 2, CONST, 1, 8),
    (A, 2, CONST, 1, 11),
    (A, 2, CONST, 0, 26),
    (A, 2, B, 1, 14),
    (D, 2, CONST, 0, 14),
    (D, 2, A, 2, 19),
    (D, 2, A, 2, 20),
    (D, 2, A, 2, 21),
    (D, 2, A, 2, 22),
    (D, 2, CONST, 1, 26),
    (C, 2, D, 2, 13),
    (C, 2, CONST, 0, 14),
    (C, 2, D, 2, 15),
    (C, 2, CONST, 0, 19),
    (C, 2, CONST, 0, 20),
    (C, 2, CONST, 1, 21),
    (C, 2, CONST, 0, 22),
    (B, 2, CONST, 1, 13),
    (B, 2, CONST, 1, 14),
    (B, 2, CONST, 0, 15),
    (B, 2, C, 2, 17),
    (B, 2, CONST, 0, 19),
    (B, 2, CONST, 0, 20),
    (B, 2, CONST, 0, 21),
    (B, 2, CONST, 0, 22),
    (A, 3, CONST, 1, 13),
    (A, 3, CONST, 1, 14),
    (A, 3, CONST, 1, 15),
    (A, 3, CONST, 0, 17),
    (A, 3, CONST, 0, 19),
    (A, 3, CONST, 0, 20),
    (A, 3, CONST, 0, 21),
    (A, 3, B, 2, 23),
    (A, 3, CONST, 1, 22),
    (A, 3, B, 2, 26),
    (D, 3, CONST, 1, 13),
    (D, 3, CONST, 1, 14),
    (D, 3, CONST, 1, 15),
    (D, 3, CONST, 0, 17),
    (D, 3, CONST, 0, 20),
    (D, 3, CONST, 1, 21),
    (D, 3, CONST, 1, 22),
    (D, 3, CONST, 0, 23),
    (D, 3, CONST, 1, 26),
    (D, 3, A, 3, 30),
    (C, 3, CONST, 1, 17),
    (C, 3, CONST, 0, 20),
    (C, 3, CONST, 0, 21),
    (C, 3, CONST, 0, 22),
    (C, 3, CONST, 0, 23),
    (C, 3, CONST, 0, 26),
    (C, 3, CONST, 1, 30),
    (C, 3, D, 3, 32),
    (B, 3, CONST, 0, 20),
    (B, 3, CONST, 1, 21),
    (B, 3, CONST, 1, 22),
    (B, 3, C, 3, 23),
    (B, 3, CONST, 1, 26),
    (B, 3, CONST, 0, 30),
    (B, 3, CONST, 0, 32),
    (A, 4, CONST, 0, 23),
    (A, 4, CONST, 0, 26),
    (A, 4, B, 3, 27),
    (A, 4, B, 3, 29),
    (A, 4, CONST, 1, 30),
    (A, 4, CONST, 0, 32),
    (D, 4, CONST, 0, 23),
    (D, 4, CONST, 0, 26),
    (D, 4, CONST, 1, 27),
    (D, 4, CONST, 1, 29),
    (D, 4, CONST, 0, 30),
    (D, 4, CONST, 1, 32),
    (C, 4, D, 4, 19),
    (C, 4, CONST, 1, 23),
    (C, 4, CONST, 1, 26),
    (C, 4, CONST, 0, 27),
    (C, 4, CONST, 0, 29),
    (C, 4, CONST, 0, 30),
    (B, 4, CONST, 0, 19),
    (B, 4, CONST, 1, 26),
    (B, 4, CONST, 1, 27),
    (B, 4, CONST, 1, 29),
    (B, 4, CONST, 0, 30)
]};

///Gets the specified bit (1-indexed) from the value - returns 0 or 1 as a u32
///Panics if bit index is not 1-32
fn get_bit(value: u32, bit: u32) -> u32 {
    if bit == 0 || bit > 32 {
        panic!("Index out of bounds.");
    }
    let mask = 1 << (bit - 1);
    let masked_value = mask & value;
    return masked_value >> (bit - 1);
}

///Calculates intermediate MD4 states when processing m from the default initial state
///Panics if m is not 16 words long.
fn get_intermediate_states(m: &Vec<u32>) -> (Vec<u32>, Vec<u32>, Vec<u32>, Vec<u32>) {


    if m.len() != 16 {
        panic!("Intermediate state function requires a 16-word input");
    }


    let x = m.clone();
    let mut a: u32 = 0x67452301;
    let mut b: u32 = 0xefcdab89;
    let mut c: u32 = 0x98badcfe;
    let mut d: u32 = 0x10325476;
    let a_init = a;
    let b_init = b;
    let c_init = c;
    let d_init = d;

    let mut a_list = vec![a];
    let mut b_list = vec![b];
    let mut c_list = vec![c];
    let mut d_list = vec![d];

    let round_1_words = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];
    let round_2_words = [0, 4, 8, 12, 1, 5, 9, 13, 2, 6, 10, 14, 3, 7, 11, 15];
    let round_3_words = [0, 8, 4, 12, 2, 10, 6, 14, 1, 9, 5, 13, 3, 11, 7, 15];

    //Round 1
    for i in 0..4 {
        a = md4_add(a, x[round_1_words[4*i]], 0,f(b, c, d), 3);
        d = md4_add(d, x[round_1_words[4*i+1]], 0, f(a, b, c), 7);
        c = md4_add(c, x[round_1_words[4*i+2]], 0, f(d, a, b), 11);
        b = md4_add(b, x[round_1_words[4*i+3]], 0, f(c, d, a), 19);
        a_list.push(a);
        b_list.push(b);
        c_list.push(c);
        d_list.push(d);
    }

    //Round 2
    for i in 0..4 {
        a = md4_add(a, x[round_2_words[4*i]], 0x5a827999, g(b, c, d), 3);
        d = md4_add(d, x[round_2_words[4*i+1]], 0x5a827999, g(a, b, c), 5);
        c = md4_add(c, x[round_2_words[4*i+2]], 0x5a827999, g(d, a, b), 9);
        b = md4_add(b, x[round_2_words[4*i+3]], 0x5a827999, g(c, d, a), 13);
        a_list.push(a);
        b_list.push(b);
        c_list.push(c);
        d_list.push(d);
    }

    //Round 3
    for i in 0..4 {
        a = md4_add(a, x[round_3_words[4*i]], 0x6ed9eba1, h(b, c, d), 3);
        d = md4_add(d, x[round_3_words[4*i+1]], 0x6ed9eba1, h(a, b, c), 9);
        c = md4_add(c, x[round_3_words[4*i+2]], 0x6ed9eba1, h(d, a, b), 11);
        b = md4_add(b, x[round_3_words[4*i+3]], 0x6ed9eba1, h(c, d, a), 15);
        a_list.push(a);
        b_list.push(b);
        c_list.push(c);
        d_list.push(d);
    }

    a = a.overflowing_add(a_init).0;
    b = b.overflowing_add(b_init).0;
    c = c.overflowing_add(c_init).0;
    d = d.overflowing_add(d_init).0;
    a_list.push(a);
    b_list.push(b);
    c_list.push(c);
    d_list.push(d);

    return (a_list, b_list, c_list, d_list);
}

///Modifies the given message to satisfy Wang's first and second round conditions
fn modify_message_round1(m: &Vec<u32>) -> Vec<u32> {
    let (mut a, mut b, mut c, mut d) = get_intermediate_states(m);
    let mut m_mod = m.clone();

    //Adjust internal variables for the first round
    for (var1, step1, var2, step2, bit) in &ROUND_1_CONDITIONS {
        let expected_value = match var2 {
            CONST => *step2 as u32,
            A => get_bit(a[*step2], *bit),
            B => get_bit(b[*step2], *bit),
            C => get_bit(c[*step2], *bit),
            D => get_bit(d[*step2], *bit)
        };
        match var1 {
            CONST => panic!("Illegally formatted condition"),
            A => a[*step1] ^= (get_bit(a[*step1], *bit) ^ expected_value).rotate_left(bit - 1),
            B => b[*step1] ^= (get_bit(b[*step1], *bit) ^ expected_value).rotate_left(bit - 1),
            C => c[*step1] ^= (get_bit(c[*step1], *bit) ^ expected_value).rotate_left(bit - 1),
            D => d[*step1] ^= (get_bit(d[*step1], *bit) ^ expected_value).rotate_left(bit - 1)
        }
    }

    //Compute modified message words
    m_mod[0] = md4_subtract(a[1], a[0], f(b[0], c[0], d[0]), 3);
    m_mod[1] = md4_subtract(d[1], d[0], f(a[1], b[0], c[0]), 7);
    m_mod[2] = md4_subtract(c[1], c[0], f(d[1], a[1], b[0]), 11);
    m_mod[3] = md4_subtract(b[1], b[0], f(c[1], d[1], a[1]), 19);
    m_mod[4] = md4_subtract(a[2], a[1], f(b[1], c[1], d[1]), 3);
    m_mod[5] = md4_subtract(d[2], d[1], f(a[2], b[1], c[1]), 7);
    m_mod[6] = md4_subtract(c[2], c[1], f(d[2], a[2], b[1]), 11);
    m_mod[7] = md4_subtract(b[2], b[1], f(c[2], d[2], a[2]), 19);
    m_mod[8] = md4_subtract(a[3], a[2], f(b[2], c[2], d[2]), 3);
    m_mod[9] = md4_subtract(d[3], d[2], f(a[3], b[2], c[2]), 7);
    m_mod[10] = md4_subtract(c[3], c[2], f(d[3], a[3], b[2]), 11);
    m_mod[11] = md4_subtract(b[3], b[2], f(c[3], d[3], a[3]), 19);
    m_mod[12] = md4_subtract(a[4], a[3], f(b[3], c[3], d[3]), 3);
    m_mod[13] = md4_subtract(d[4], d[3], f(a[4], b[3], c[3]), 7);
    m_mod[14] = md4_subtract(c[4], c[3], f(d[4], a[4], b[3]), 11);
    m_mod[15] = md4_subtract(b[4], b[3], f(c[4], d[4], a[4]), 19);

    return m_mod;
}

///Modifies the given message to correct a_5
fn modify_message_round2(m: &Vec<u32>) -> Vec<u32> {
    let mut m_mod = m.clone();

    //Apply corrections to a_5
    for i in [19, 26, 27, 29, 32] {
        let (a, b, c, d) = get_intermediate_states(&m_mod);
        let a_expected = {
            if i == 19 {
                get_bit(c[4], i)
            }
            else if i == 27 {
                0
            }
            else {
                1
            }
        };

        if get_bit(a[5], i) != a_expected {
            m_mod[0] ^= 1 << (i-4);
            let a_1 = md4_add(a[0], m_mod[0], 0, f(b[0], c[0], d[0]), 3);
            m_mod[1] = md4_subtract(d[1], d[0], f(a_1, b[0], c[0]), 7);
            let d_1 = md4_add(d[0], m_mod[1], 0, f(a_1, b[0], c[0]), 7);
            m_mod[2] = md4_subtract(c[1], c[0], f(d_1, a_1, b[0]), 11);
            let c_1 = md4_add(c[0], m_mod[2], 0, f(d_1, a_1, b[0]), 11);
            m_mod[3] = md4_subtract(b[1], b[0], f(c_1, d_1, a_1), 19);
            let b_1 = md4_add(b[0], m_mod[3], 0, f(c_1, d_1, a_1), 19);
            m_mod[4] = md4_subtract(a[2], a_1, f(b_1, c_1, d_1), 3);
        }
    }

    return m_mod;
}

fn challenge55() -> (Vec<u8>, Vec<u8>) {
    let mut m = vec![0; 16];
    let mut attempts = 0;
    loop {
        attempts += 1;
        //Create random M
        for i in 0..16 {
            m[i] = random();
        }

        //Apply tweaks
        m = modify_message_round1(&m);
        m = modify_message_round2(&m);

        //Create M' from original message
        let mut m_prime = m.clone();
        m_prime[1] = m_prime[1].overflowing_add(1<<31).0;
        m_prime[2] = m_prime[2].overflowing_add(1<<31).0.overflowing_sub(1<<28).0;
        m_prime[12] = m_prime[12].overflowing_sub(1<<16).0;

        let (a, b, c, d) = get_intermediate_states(&m);
        let (a_prime, b_prime, c_prime, d_prime) = get_intermediate_states(&(m_prime));

        if a[13] == a_prime[13] && b[13] == b_prime[13] && c[13] == c_prime[13] && d[13] == d_prime[13] {
            let mut m_bytes = vec![];
            let mut m_prime_bytes = vec![];

            for i in 0..16 {
                m_bytes.append(&mut m[i].to_le_bytes().to_vec());
                m_prime_bytes.append(&mut m_prime[i].to_le_bytes().to_vec());
            }

            return (m_bytes, m_prime_bytes);
        }

        //Exit with bad output if we make too many attempts
        if attempts > 10000000 {
            return (vec![], vec![]);
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::hash::Hash;
    use super::*;

    #[test]
    fn test_solution() {
        let hash = Hash::MD4;
        let (m1, m2) = challenge55();
        assert_ne!(m1, m2);
        assert_eq!(hash.digest(&m1), hash.digest(&m2));
    }
}