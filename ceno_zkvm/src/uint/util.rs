pub(crate) const fn max_degree_2_carry_value(m: usize, c: usize) -> u64 {
    assert!(m <= u64::BITS as usize);
    let num_cells = (m + c - 1) / c;
    let max_carry_value: u128 = ((1 << c) - 1) as u128 * ((1 << c) - 1 ) as u128 // 2^C * 2^C
        * (2 * num_cells - 1) as u128
        / (1 << c) as u128; // max number of limbs for degree 2 mul
    assert!(max_carry_value <= u64::MAX as u128);
    max_carry_value as u64
}
