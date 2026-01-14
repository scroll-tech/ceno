extern crate ceno_rt;

fn main() {
    // Compute the (1 << log_n) 'th fibonacci number, using normal Rust code.
    let log_n: u32 = ceno_rt::read();
    let mut a = 0_u32;
    let mut b = 1_u32;
    let n = 1 << log_n;
    for _ in 0..n {
        let mut c = a + b;
        c %= 7919; // Modulus to prevent overflow.
        a = b;
        b = c;
    }
    // Constrain with public io
    ceno_rt::commit(&b);
}
