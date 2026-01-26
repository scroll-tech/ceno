use ff_ext::ExtensionField;
use itertools::Itertools;
use multilinear_extensions::mle::Point;

pub struct BooleanHypercube {
    num_vars: usize,
}

// 2^5-1 cyclic group
pub const CYCLIC_POW2_5: [u64; 32] = [
    0b00001, // 0 = decimal 1
    0b00010, // 1 = decimal 2
    0b00100, // 2 = decimal 4
    0b01000, // 3 = decimal 8
    0b10000, // 4 = decimal 16
    0b00101, // 5 = decimal 5
    0b01010, // 6 = decimal 10
    0b10100, // 7 = decimal 20
    0b01101, // 8 = decimal 13
    0b11010, // 9 = decimal 26
    0b10001, // 10 = decimal 17
    0b00111, // 11 = decimal 7
    0b01110, // 12 = decimal 14
    0b11100, // 13 = decimal 28
    0b11101, // 14 = decimal 29
    0b11111, // 15 = decimal 31
    0b11011, // 16 = decimal 27
    0b10011, // 17 = decimal 19
    0b00011, // 18 = decimal 3
    0b00110, // 19 = decimal 6
    0b01100, // 20 = decimal 12
    0b11000, // 21 = decimal 24
    0b10101, // 22 = decimal 21
    0b01111, // 23 = decimal 15
    0b11110, // 24 = decimal 30
    0b11001, // 25 = decimal 25
    0b10111, // 26 = decimal 23
    0b01011, // 27 = decimal 11
    0b10110, // 28 = decimal 22
    0b01001, // 29 = decimal 9
    0b10010, // 30 = decimal 18
    0b00001, // 31 = decimal 1
];
#[allow(dead_code)]
const CYCLIC_POW2_5_MODULUS: u8 = 0b100101; // X^5 + X^2 + 1

// 2^6-1 cyclic group
pub const CYCLIC_POW2_6: [u64; 64] = [
    0b000001, // 0 = decimal 1
    0b000010, // 1 = decimal 2
    0b000100, // 2 = decimal 4
    0b001000, // 3 = decimal 8
    0b010000, // 4 = decimal 16
    0b100000, // 5 = decimal 32
    0b000011, // 6 = decimal 3
    0b000110, // 7 = decimal 6
    0b001100, // 8 = decimal 12
    0b011000, // 9 = decimal 24
    0b110000, // 10 = decimal 48
    0b100011, // 11 = decimal 35
    0b000101, // 12 = decimal 5
    0b001010, // 13 = decimal 10
    0b010100, // 14 = decimal 20
    0b101000, // 15 = decimal 40
    0b010011, // 16 = decimal 19
    0b100110, // 17 = decimal 38
    0b001111, // 18 = decimal 15
    0b011110, // 19 = decimal 30
    0b111100, // 20 = decimal 60
    0b111011, // 21 = decimal 59
    0b110101, // 22 = decimal 53
    0b101001, // 23 = decimal 41
    0b010001, // 24 = decimal 17
    0b100010, // 25 = decimal 34
    0b000111, // 26 = decimal 7
    0b001110, // 27 = decimal 14
    0b011100, // 28 = decimal 28
    0b111000, // 29 = decimal 56
    0b110011, // 30 = decimal 51
    0b100101, // 31 = decimal 37
    0b001001, // 32 = decimal 9
    0b010010, // 33 = decimal 18
    0b100100, // 34 = decimal 36
    0b001011, // 35 = decimal 11
    0b010110, // 36 = decimal 22
    0b101100, // 37 = decimal 44
    0b011011, // 38 = decimal 27
    0b110110, // 39 = decimal 54
    0b101111, // 40 = decimal 47
    0b011101, // 41 = decimal 29
    0b111010, // 42 = decimal 58
    0b110111, // 43 = decimal 55
    0b101101, // 44 = decimal 45
    0b011001, // 45 = decimal 25
    0b110010, // 46 = decimal 50
    0b100111, // 47 = decimal 39
    0b001101, // 48 = decimal 13
    0b011010, // 49 = decimal 26
    0b110100, // 50 = decimal 52
    0b101011, // 51 = decimal 43
    0b010101, // 52 = decimal 21
    0b101010, // 53 = decimal 42
    0b010111, // 54 = decimal 23
    0b101110, // 55 = decimal 46
    0b011111, // 56 = decimal 31
    0b111110, // 57 = decimal 62
    0b111111, // 58 = decimal 63
    0b111101, // 59 = decimal 61
    0b111001, // 60 = decimal 57
    0b110001, // 61 = decimal 49
    0b100001, // 62 = decimal 33
    0b000001, // 63 = decimal 1
];
#[allow(dead_code)]
const CYCLIC_POW2_6_MODULUS: u8 = 0b1000011; // X^6 + X + 1

impl BooleanHypercube {
    // giving num_vars, cyclic group size is 2^num_vars - 1, as excluding 0
    pub fn new(num_vars: usize) -> Self {
        assert!(num_vars == 5 || num_vars == 6);
        Self { num_vars }
    }

    pub fn get_rotation_points<E: ExtensionField>(&self, point: &Point<E>) -> (Point<E>, Point<E>) {
        match self.num_vars {
            5 => (
                // derive from CYCLIC_POW2_5_MODULUS
                // left: (0, r0, r1, r2, r3, r5, r6, ....)
                std::iter::once(E::ZERO)
                    .chain(point[..4].iter().copied())
                    .chain(point[5..].iter().copied())
                    .take(point.len())
                    .collect_vec(),
                // right: (1, r0, 1-r1, r2, r3, r5, r6, ....)
                std::iter::once(E::ONE)
                    .chain(std::iter::once(point[0]))
                    .chain(std::iter::once(E::ONE - point[1]))
                    .chain(point[2..4].iter().copied())
                    .chain(point[5..].iter().copied())
                    .take(point.len())
                    .collect_vec(),
            ),
            6 => (
                // derive from CYCLIC_POW2_6_MODULUS
                // left: (0, r0, r1, r2, r3, r4, r6, r7, ....)
                std::iter::once(E::ZERO)
                    .chain(point[..5].iter().copied())
                    .chain(point[6..].iter().copied())
                    .take(point.len())
                    .collect_vec(),
                // right: (1, 1 - r0, r1, r2, r3, r4, r6, r7, ....)
                std::iter::once(E::ONE)
                    .chain(std::iter::once(E::ONE - point[0]))
                    .chain(std::iter::once(point[1]))
                    .chain(point[2..5].iter().copied())
                    .chain(point[6..].iter().copied())
                    .take(point.len())
                    .collect_vec(),
            ),
            num_vars => unimplemented!("not support {num_vars}"),
        }
    }

    pub fn get_rotation_right_eval_from_left<E: ExtensionField>(
        &self,
        rotated_eval: E,
        left_eval: E,
        point: &Point<E>,
    ) -> E {
        match self.num_vars {
            // rotated_eval = (1-r4) * left_eval + r4 * right_eval
            // right_eval = (rotated_eval - (1-r4) * left_eval) / r4
            5 => (rotated_eval - (E::ONE - point[4]) * left_eval) / point[4],
            // rotated_eval = (1-r5) * left_eval + r5 * right_eval
            // right_eval = (rotated_eval - (1-r5) * left_eval) / r5
            6 => (rotated_eval - (E::ONE - point[5]) * left_eval) / point[5],
            num_vars => unimplemented!("not support {num_vars}"),
        }
    }
}

impl IntoIterator for &BooleanHypercube {
    type Item = u64;
    type IntoIter = std::iter::Copied<std::slice::Iter<'static, u64>>;

    fn into_iter(self) -> Self::IntoIter {
        match self.num_vars {
            5 => CYCLIC_POW2_5.as_slice().iter().copied(),
            6 => CYCLIC_POW2_6.as_slice().iter().copied(),
            _ => panic!("not support {}", self.num_vars),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use crate::gkr::booleanhypercube::{CYCLIC_POW2_5_MODULUS, CYCLIC_POW2_6_MODULUS};

    #[test]
    fn test_generate_f_31_cyclic_group_element() {
        let _x = 0b00010; // generator x = X
        let mut powers = Vec::with_capacity(31);
        powers.push(1); // x^0 = 1

        let mut current = 1u8;

        for _ in 1..32 {
            current <<= 1; // multiply by x (shift left)
            if current & 0b100000 != 0 {
                // degree 5 overflow
                current ^= CYCLIC_POW2_5_MODULUS; // reduce modulo polynomial
            }
            powers.push(current);
        }

        let set = powers.iter().cloned().collect::<HashSet<u8>>();
        assert_eq!(set.len(), 31); // all elements are unique
    }

    #[test]
    fn test_generate_f_63_cyclic_group_element() {
        let _x = 0b000010; // generator x = X
        let mut powers = Vec::with_capacity(63);
        powers.push(1); // x^0 = 1

        let mut current = 1u8;

        for _ in 1..64 {
            current <<= 1; // multiply by x (shift left)
            if current & 0b1000000 != 0 {
                // degree 6 overflow
                current ^= CYCLIC_POW2_6_MODULUS; // reduce modulo polynomial
            }
            powers.push(current);
        }

        let set = powers.iter().cloned().collect::<HashSet<u8>>();
        assert_eq!(set.len(), 63); // all elements are unique
    }
}
