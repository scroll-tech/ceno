// split single u64 value into W slices, each slice got C bits.
// all the rest slices will be filled with 0 if W x C > 64
pub fn u64vec<const W: usize, const C: usize>(mut x: u64) -> [u64; W] {
    assert!(C <= 64);
    let mut ret = [0; W];
    for item in &mut ret {
        *item = x & !(u64::MAX << C);
        x >>= C;
    }
    ret
}
