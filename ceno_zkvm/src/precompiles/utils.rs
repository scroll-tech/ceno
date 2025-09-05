use ff_ext::ExtensionField;
use generic_array::typenum::Unsigned;
use gkr_iop::circuit_builder::expansion_expr;
use itertools::Itertools;
use multilinear_extensions::{Expression, ToExpr};
use p3::field::FieldAlgebra;
use sp1_curves::params::{Limbs, NumLimbs, NumWords};

pub fn not8_expr<E: ExtensionField>(expr: Expression<E>) -> Expression<E> {
    E::BaseField::from_canonical_u8(0xFF).expr() - expr
}

pub fn set_slice_felts_from_u64<E, I>(dst: &mut [E::BaseField], start_index: usize, iter: I)
where
    E: ExtensionField,
    I: IntoIterator<Item = u64>,
{
    for (i, word) in iter.into_iter().enumerate() {
        dst[start_index + i] = E::BaseField::from_canonical_u64(word);
    }
}

/// Merge a slice of u8 limbs into a slice of u32 represented by u16 limb pair.
pub fn merge_u8_limbs_to_u16_limbs_pairs_and_extend<E: ExtensionField, P: NumLimbs + NumWords>(
    u8_limbs: &Limbs<impl ToExpr<E, Output = Expression<E>> + Clone, P::Limbs>,
    dst: &mut Vec<[Expression<E>; 2]>,
) {
    for i in 0..P::WordsFieldElement::USIZE {
        // create an expression combining 4 elements of bytes into a 2x16-bit felt
        let output8_slice = u8_limbs.0[4 * i..4 * (i + 1)]
            .iter()
            .map(|e| (8, e.expr()))
            .collect_vec();
        dst.push([
            expansion_expr::<E, 16>(&output8_slice[0..2]),
            expansion_expr::<E, 16>(&output8_slice[2..4]),
        ])
    }
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
                mask += (1 << i) * bit_iter.next().unwrap();
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
}

#[cfg(test)]
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
