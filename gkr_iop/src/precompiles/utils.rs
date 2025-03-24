use ff_ext::ExtensionField;
use itertools::Itertools;
use p3_field::PrimeCharacteristicRing;
use subprotocols::expression::{Constant, Expression};

use crate::evaluation::EvalExpression;

pub fn zero_expr() -> Expression {
    Expression::Const(Constant::Base(0))
}

pub fn one_expr() -> Expression {
    Expression::Const(Constant::Base(1))
}

pub fn not8_expr(expr: Expression) -> Expression {
    Expression::Const(Constant::Base(0xFF)) - expr
}

pub fn zero_eval() -> EvalExpression {
    EvalExpression::Linear(0, Constant::Base(0), Constant::Base(0))
}

pub fn nest<E: ExtensionField>(v: &Vec<E::BaseField>) -> Vec<Vec<E::BaseField>> {
    v.clone().into_iter().map(|e| vec![e]).collect_vec()
}

pub fn u64s_to_felts<E: ExtensionField>(words: Vec<u64>) -> Vec<E::BaseField> {
    words
        .into_iter()
        .map(|word| E::BaseField::from_u64(word))
        .collect()
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Mask {
    pub size: usize,
    pub value: u64,
}

impl Mask {
    pub fn new(size: usize, value: u64) -> Self {
        if size < 64 {
            assert!(value < (1 << size));
        }
        Self { size, value }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MaskRepresentation {
    pub rep: Vec<Mask>,
}

impl From<Mask> for (usize, u64) {
    fn from(mask: Mask) -> Self {
        (mask.size, mask.value)
    }
}

impl From<(usize, u64)> for Mask {
    fn from(tuple: (usize, u64)) -> Self {
        Mask::new(tuple.0, tuple.1)
    }
}

impl From<MaskRepresentation> for Vec<(usize, u64)> {
    fn from(mask_rep: MaskRepresentation) -> Self {
        mask_rep.rep.into_iter().map(|mask| mask.into()).collect()
    }
}

impl From<Vec<(usize, u64)>> for MaskRepresentation {
    fn from(tuples: Vec<(usize, u64)>) -> Self {
        MaskRepresentation {
            rep: tuples.into_iter().map(|tuple| tuple.into()).collect(),
        }
    }
}

impl MaskRepresentation {
    pub fn new(masks: Vec<Mask>) -> Self {
        Self { rep: masks }
    }

    pub fn from_bits(bits: Vec<u64>, sizes: Vec<usize>) -> Self {
        assert_eq!(bits.len(), sizes.iter().sum::<usize>());
        let mut masks = Vec::new();
        let mut bit_iter = bits.into_iter();
        for size in sizes {
            let mut mask = 0;
            for i in 0..size {
                mask += (1 << i) * (bit_iter.next().unwrap() as u64);
            }
            masks.push(Mask::new(size, mask));
        }
        Self { rep: masks }
    }

    pub fn to_bits(&self) -> Vec<u64> {
        self.rep
            .iter()
            .flat_map(|mask| (0..mask.size).map(move |i| ((mask.value >> i) & 1)))
            .collect()
    }

    pub fn convert(&self, new_sizes: Vec<usize>) -> Self {
        let bits = self.to_bits();
        Self::from_bits(bits, new_sizes)
    }

    pub fn values(&self) -> Vec<u64> {
        self.rep.iter().map(|m| m.value).collect_vec()
    }

    pub fn masks(&self) -> Vec<Mask> {
        self.rep.clone()
    }

    fn len(&self) -> usize {
        self.rep.len()
    }
}

#[derive(Debug)]
pub enum CenoLookup {
    And(Expression, Expression, Expression),
    Xor(Expression, Expression, Expression),
    U16(Expression),
}

impl CenoLookup {
    // combine lookup arguments with challenges
    pub fn compress(&self, alpha: Constant, beta: Constant) -> Expression {
        let [alpha, beta] = [alpha, beta].map(|e| {
            // assert!(matches!(e, Constant::Challenge(_)));
            Expression::Const(e)
        });

        match self {
            CenoLookup::And(a, b, c) => {
                a.clone()
                    + alpha.clone() * b.clone()
                    + alpha.clone() * alpha.clone() * c.clone()
                    + beta
            }
            CenoLookup::Xor(a, b, c) => {
                a.clone()
                    + alpha.clone() * b.clone()
                    + alpha.clone() * alpha.clone() * c.clone()
                    + beta
            }
            CenoLookup::U16(a) => a.clone() + beta,
        }
    }
}

mod tests {
    use crate::precompiles::utils::{Mask, MaskRepresentation};

    #[test]
    fn test_mask_representation_from_bits() {
        let bits = vec![1, 0, 1, 1, 0, 1, 0, 0];
        let sizes = vec![3, 5];
        let mask_rep = MaskRepresentation::from_bits(bits.clone(), sizes.clone());
        assert_eq!(mask_rep.rep.len(), 2);
        assert_eq!(mask_rep.rep[0], Mask::new(3, 0b101));
        assert_eq!(mask_rep.rep[1], Mask::new(5, 0b00101));
    }

    #[test]
    fn test_mask_representation_to_bits() {
        let masks = vec![Mask::new(3, 0b101), Mask::new(5, 0b00101)];
        let mask_rep = MaskRepresentation::new(masks);
        let bits = mask_rep.to_bits();
        assert_eq!(bits, vec![1, 0, 1, 1, 0, 1, 0, 0]);
    }

    #[test]
    fn test_mask_representation_convert() {
        let bits = vec![1, 0, 1, 1, 0, 1, 0, 0];
        let sizes = vec![3, 5];
        let mask_rep = MaskRepresentation::from_bits(bits.clone(), sizes.clone());
        let new_sizes = vec![4, 4];
        let new_mask_rep = mask_rep.convert(new_sizes);
        assert_eq!(new_mask_rep.rep.len(), 2);
        assert_eq!(new_mask_rep.rep[0], Mask::new(4, 0b1101));
        assert_eq!(new_mask_rep.rep[1], Mask::new(4, 0b0010));
    }
}
