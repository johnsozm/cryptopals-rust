use rand::random;

///Gets the specified bit (1-indexed) from the value - returns 0 or 1 as a u32
///Panics if bit index is not 1-32
fn get_bit(value: u32, bit: usize) -> u32 {
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


    //Round 1
    a = a.overflowing_add(x[0]).0.overflowing_add((b&c)|((!b)&d)).0.rotate_left(3);
    d = d.overflowing_add(x[1]).0.overflowing_add((a&b)|((!a)&c)).0.rotate_left(7);
    c = c.overflowing_add(x[2]).0.overflowing_add((d&a)|((!d)&b)).0.rotate_left(11);
    b = b.overflowing_add(x[3]).0.overflowing_add((c&d)|((!c)&a)).0.rotate_left(19);
    a_list.push(a);
    b_list.push(b);
    c_list.push(c);
    d_list.push(d);

    a = a.overflowing_add(x[4]).0.overflowing_add((b&c)|((!b)&d)).0.rotate_left(3);
    d = d.overflowing_add(x[5]).0.overflowing_add((a&b)|((!a)&c)).0.rotate_left(7);
    c = c.overflowing_add(x[6]).0.overflowing_add((d&a)|((!d)&b)).0.rotate_left(11);
    b = b.overflowing_add(x[7]).0.overflowing_add((c&d)|((!c)&a)).0.rotate_left(19);
    a_list.push(a);
    b_list.push(b);
    c_list.push(c);
    d_list.push(d);

    a = a.overflowing_add(x[8]).0.overflowing_add((b&c)|((!b)&d)).0.rotate_left(3);
    d = d.overflowing_add(x[9]).0.overflowing_add((a&b)|((!a)&c)).0.rotate_left(7);
    c = c.overflowing_add(x[10]).0.overflowing_add((d&a)|((!d)&b)).0.rotate_left(11);
    b = b.overflowing_add(x[11]).0.overflowing_add((c&d)|((!c)&a)).0.rotate_left(19);
    a_list.push(a);
    b_list.push(b);
    c_list.push(c);
    d_list.push(d);

    a = a.overflowing_add(x[12]).0.overflowing_add((b&c)|((!b)&d)).0.rotate_left(3);
    d = d.overflowing_add(x[13]).0.overflowing_add((a&b)|((!a)&c)).0.rotate_left(7);
    c = c.overflowing_add(x[14]).0.overflowing_add((d&a)|((!d)&b)).0.rotate_left(11);
    b = b.overflowing_add(x[15]).0.overflowing_add((c&d)|((!c)&a)).0.rotate_left(19);
    a_list.push(a);
    b_list.push(b);
    c_list.push(c);
    d_list.push(d);

    //Round 2
    a = a.overflowing_add(x[0]).0.overflowing_add(0x5a827999).0.overflowing_add((b&c)|(c&d)|(b&d)).0.rotate_left(3);
    d = d.overflowing_add(x[4]).0.overflowing_add(0x5a827999).0.overflowing_add((a&b)|(b&c)|(a&c)).0.rotate_left(5);
    c = c.overflowing_add(x[8]).0.overflowing_add(0x5a827999).0.overflowing_add((d&a)|(a&b)|(d&b)).0.rotate_left(9);
    b = b.overflowing_add(x[12]).0.overflowing_add(0x5a827999).0.overflowing_add((c&d)|(d&a)|(c&a)).0.rotate_left(13);
    a_list.push(a);
    b_list.push(b);
    c_list.push(c);
    d_list.push(d);

    a = a.overflowing_add(x[1]).0.overflowing_add(0x5a827999).0.overflowing_add((b&c)|(c&d)|(b&d)).0.rotate_left(3);
    d = d.overflowing_add(x[5]).0.overflowing_add(0x5a827999).0.overflowing_add((a&b)|(b&c)|(a&c)).0.rotate_left(5);
    c = c.overflowing_add(x[9]).0.overflowing_add(0x5a827999).0.overflowing_add((d&a)|(a&b)|(d&b)).0.rotate_left(9);
    b = b.overflowing_add(x[13]).0.overflowing_add(0x5a827999).0.overflowing_add((c&d)|(d&a)|(c&a)).0.rotate_left(13);
    a_list.push(a);
    b_list.push(b);
    c_list.push(c);
    d_list.push(d);

    a = a.overflowing_add(x[2]).0.overflowing_add(0x5a827999).0.overflowing_add((b&c)|(c&d)|(b&d)).0.rotate_left(3);
    d = d.overflowing_add(x[6]).0.overflowing_add(0x5a827999).0.overflowing_add((a&b)|(b&c)|(a&c)).0.rotate_left(5);
    c = c.overflowing_add(x[10]).0.overflowing_add(0x5a827999).0.overflowing_add((d&a)|(a&b)|(d&b)).0.rotate_left(9);
    b = b.overflowing_add(x[14]).0.overflowing_add(0x5a827999).0.overflowing_add((c&d)|(d&a)|(c&a)).0.rotate_left(13);
    a_list.push(a);
    b_list.push(b);
    c_list.push(c);
    d_list.push(d);

    a = a.overflowing_add(x[3]).0.overflowing_add(0x5a827999).0.overflowing_add((b&c)|(c&d)|(b&d)).0.rotate_left(3);
    d = d.overflowing_add(x[7]).0.overflowing_add(0x5a827999).0.overflowing_add((a&b)|(b&c)|(a&c)).0.rotate_left(5);
    c = c.overflowing_add(x[11]).0.overflowing_add(0x5a827999).0.overflowing_add((d&a)|(a&b)|(d&b)).0.rotate_left(9);
    b = b.overflowing_add(x[15]).0.overflowing_add(0x5a827999).0.overflowing_add((c&d)|(d&a)|(c&a)).0.rotate_left(13);
    a_list.push(a);
    b_list.push(b);
    c_list.push(c);
    d_list.push(d);

    //Round 3
    a = a.overflowing_add(x[0]).0.overflowing_add(0x6ed9eba1).0.overflowing_add(b^c^d).0.rotate_left(3);
    d = d.overflowing_add(x[8]).0.overflowing_add(0x6ed9eba1).0.overflowing_add(a^b^c).0.rotate_left(9);
    c = c.overflowing_add(x[4]).0.overflowing_add(0x6ed9eba1).0.overflowing_add(d^a^b).0.rotate_left(11);
    b = b.overflowing_add(x[12]).0.overflowing_add(0x6ed9eba1).0.overflowing_add(c^d^a).0.rotate_left(15);
    a_list.push(a);
    b_list.push(b);
    c_list.push(c);
    d_list.push(d);

    a = a.overflowing_add(x[2]).0.overflowing_add(0x6ed9eba1).0.overflowing_add(b^c^d).0.rotate_left(3);
    d = d.overflowing_add(x[10]).0.overflowing_add(0x6ed9eba1).0.overflowing_add(a^b^c).0.rotate_left(9);
    c = c.overflowing_add(x[6]).0.overflowing_add(0x6ed9eba1).0.overflowing_add(d^a^b).0.rotate_left(11);
    b = b.overflowing_add(x[14]).0.overflowing_add(0x6ed9eba1).0.overflowing_add(c^d^a).0.rotate_left(15);
    a_list.push(a);
    b_list.push(b);
    c_list.push(c);
    d_list.push(d);

    a = a.overflowing_add(x[1]).0.overflowing_add(0x6ed9eba1).0.overflowing_add(b^c^d).0.rotate_left(3);
    d = d.overflowing_add(x[9]).0.overflowing_add(0x6ed9eba1).0.overflowing_add(a^b^c).0.rotate_left(9);
    c = c.overflowing_add(x[5]).0.overflowing_add(0x6ed9eba1).0.overflowing_add(d^a^b).0.rotate_left(11);
    b = b.overflowing_add(x[13]).0.overflowing_add(0x6ed9eba1).0.overflowing_add(c^d^a).0.rotate_left(15);
    a_list.push(a);
    b_list.push(b);
    c_list.push(c);
    d_list.push(d);

    a = a.overflowing_add(x[3]).0.overflowing_add(0x6ed9eba1).0.overflowing_add(b^c^d).0.rotate_left(3);
    d = d.overflowing_add(x[11]).0.overflowing_add(0x6ed9eba1).0.overflowing_add(a^b^c).0.rotate_left(9);
    c = c.overflowing_add(x[7]).0.overflowing_add(0x6ed9eba1).0.overflowing_add(d^a^b).0.rotate_left(11);
    b = b.overflowing_add(x[15]).0.overflowing_add(0x6ed9eba1).0.overflowing_add(c^d^a).0.rotate_left(15);
    a_list.push(a);
    b_list.push(b);
    c_list.push(c);
    d_list.push(d);

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
fn modify_message(m: &Vec<u32>) -> Vec<u32> {
    //TODO: Implement
    return m.clone();
}

fn challenge55() -> (Vec<u8>, Vec<u8>) {
    let mut m = vec![0; 16];
    loop {
        //Create random M
        for i in 0..16 {
            m[i] = random();
        }

        //Apply tweaks
        m = modify_message(&m);

        //Create M'
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
        assert_neq!(m1, m2);
        assert_eq!(hash.digest(&m1), hash.digest(&m2));
    }
}