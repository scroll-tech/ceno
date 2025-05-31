const BH_MAX_NUM_VAR: usize = 5;

pub struct BooleanHypercube {
    cyclic_group: Vec<u64>,
}

impl BooleanHypercube {
    // giving num_vars, cyclic group size is 2^num_vars - 1, as excluding 0
    pub fn new(num_vars: usize) -> Self {
        assert!(num_vars <= BH_MAX_NUM_VAR);
        match num_vars {
            5 => BooleanHypercube {
                cyclic_group: vec![
                    0b00001, // X^0  = (1, 0, 0, 0, 0)
                    0b00010, // X^1  = (0, 1, 0, 0, 0) // assume this to be generator
                    0b00100, // X^2  = (0, 0, 1, 0, 0)
                    0b01000, // X^3  = (0, 0, 0, 1, 0)
                    0b10000, // X^4  = (0, 0, 0, 0, 1)
                    0b00101, // X^5  = X^2 + 1
                    0b01010, // X^6  = X^3 + X
                    0b10100, // X^7  = X^4 + X^2
                    0b01101, // X^8  = X^3 + X^2 + 1
                    0b11010, // X^9  = X^4 + X^3 + X
                    0b10001, // X^10 = X^4 + 1
                    0b00111, // X^11 = X^2 + X + 1
                    0b01110, // X^12 = X^3 + X^2 + X
                    0b11100, // X^13 = X^4 + X^3 + X^2
                    0b11101, // X^14 = X^4 + X^3 + X^2 + 1
                    0b11111, // X^15 = X^4 + X^3 + X^2 + X + 1
                    0b11011, // X^16 = X^4 + X^3 + X + 1
                    0b10011, // X^17 = X^4 + X + 1
                    0b00011, // X^18 = X + 1
                    0b00110, // X^19 = X^2 + X
                    0b01100, // X^20 = X^3 + X^2
                    0b11000, // X^21 = X^4 + X^3
                    0b10101, // X^22 = X^4 + X^2 + 1
                    0b01111, // X^23 = X^3 + X^2 + X + 1
                    0b11110, // X^24 = X^4 + X^3 + X^2 + X
                    0b10011, // X^25 = X^4 + X^3 + 1
                    0b10111, // X^26 = X^4 + X^2 + X + 1
                    0b01011, // X^27 = X^3 + X + 1
                    0b01101, // X^28 = X^4 + X^2 + X
                    0b01001, // X^29 = X^3 + 1
                    0b10010, // X^30 = X^4 + X
                    0b00001, // X^31 = 1 (cyclic repeat of X^0)
                ],
            },
            _ => unimplemented!(),
        }
    }
}

pub struct BooleanHypercubeIter<'a> {
    cube: &'a BooleanHypercube,
    pos: usize,
}

impl<'a> IntoIterator for &'a BooleanHypercube {
    type Item = u64;
    type IntoIter = BooleanHypercubeIter<'a>;

    fn into_iter(self) -> Self::IntoIter {
        BooleanHypercubeIter { cube: self, pos: 0 }
    }
}

impl<'a> Iterator for BooleanHypercubeIter<'a> {
    type Item = u64;

    fn next(&mut self) -> Option<Self::Item> {
        if self.pos < self.cube.cyclic_group.len() {
            let val = self.cube.cyclic_group[self.pos];
            self.pos += 1;
            Some(val)
        } else {
            None
        }
    }
}
