use ff_ext::ExtensionField;
use itertools::Itertools;
use multilinear_extensions::mle::Point;

const BH_MAX_NUM_VAR: usize = 5;

pub struct BooleanHypercube {
    num_vars: usize,
}

// 2^5-1 cyclic group
const CYCLIC_POW2_5: [u64; 32] = [
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

impl BooleanHypercube {
    // giving num_vars, cyclic group size is 2^num_vars - 1, as excluding 0
    pub fn new(num_vars: usize) -> Self {
        assert!(num_vars <= BH_MAX_NUM_VAR);
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
            // rotated_eval = (1-r4) * left_eval - r4 * right_eval
            // right_eval = ((1-r4) * left_eval - rotated_eval) / r4
            5 => ((E::ONE - point[4]) * left_eval - rotated_eval) / point[4],
            num_vars => unimplemented!("not support {num_vars}"),
        }
    }
}

impl IntoIterator for &BooleanHypercube {
    type Item = u64;
    type IntoIter = std::array::IntoIter<u64, 32>;

    fn into_iter(self) -> Self::IntoIter {
        match self.num_vars {
            5 => CYCLIC_POW2_5.into_iter(),
            _ => unimplemented!(),
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::gkr::booleanhypercube::CYCLIC_POW2_5_MODULUS;

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

        for (i, &val) in powers.iter().enumerate() {
            println!("0b{:05b}, // {} = decimal {} ", val, i, val);
        }
    }
}
