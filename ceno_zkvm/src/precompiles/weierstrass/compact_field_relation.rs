use derive::AlignedBorrow;
use ff_ext::{ExtensionField, SmallField};
use generic_array::{GenericArray, sequence::GenericSequence, typenum::Unsigned};
use gkr_iop::{circuit_builder::CircuitBuilder, error::CircuitBuilderError};
use multilinear_extensions::{Expression, ToExpr, WitIn};
use num::BigUint;
use p3::field::PrimeCharacteristicRing;
use sp1_curves::{
    params::{FieldParameters, Limbs, NumLimbs, limbs_expr_from_vec, limbs_from_vec},
    polynomial::Polynomial,
};
use typenum::U63;

use crate::{
    gadgets::{
        util::{compute_root_quotient_and_shift, split_u16_limbs_to_u8_limbs},
        util_expr::{eval_field_operation, poly_mul_expr},
    },
    witness::LkMultiplicity,
};

// Compact relation audit checklist:
// - Every caller-owned compact limb array must get explicit assert_bytes/assert_byte_fields.
// - This helper always byte-checks quotient and witness limbs in populate and eval.
// - Structural stats should show lookups reduced by removed FieldOpCols, not dropped near zero.

fn to_compact_relation_limbs_field<E, F>(x: &BigUint) -> Limbs<E, U63>
where
    E: From<F>,
    F: p3::field::Field,
{
    let mut bytes = x.to_bytes_le();
    bytes.resize(U63::USIZE, 0);
    limbs_from_vec(bytes.into_iter().map(F::from_u8).collect())
}

fn to_compact_relation_limbs_expr<E>(x: &BigUint) -> Limbs<Expression<E>, U63>
where
    E: ExtensionField,
{
    let mut bytes = x.to_bytes_le();
    bytes.resize(U63::USIZE, 0);
    limbs_expr_from_vec(bytes.into_iter().map(E::BaseField::from_u8).collect())
}

#[derive(Clone, Debug, AlignedBorrow)]
#[repr(C)]
pub struct CompactFieldRelationCols<WitT, P: FieldParameters + NumLimbs> {
    pub(crate) quotient: Limbs<WitT, U63>,
    pub(crate) witness_low: Limbs<WitT, U63>,
    pub(crate) witness_high: Limbs<WitT, U63>,
    pub(crate) _marker: std::marker::PhantomData<P>,
}

impl<P: FieldParameters + NumLimbs> CompactFieldRelationCols<WitIn, P> {
    pub fn create<E: ExtensionField, NR, N>(cb: &mut CircuitBuilder<E>, name_fn: N) -> Self
    where
        NR: Into<String>,
        N: FnOnce() -> NR,
    {
        let name: String = name_fn().into();
        Self {
            quotient: Limbs(GenericArray::generate(|_| {
                cb.create_witin(|| format!("{}_quotient", name))
            })),
            witness_low: Limbs(GenericArray::generate(|_| {
                cb.create_witin(|| format!("{}_witness_low", name))
            })),
            witness_high: Limbs(GenericArray::generate(|_| {
                cb.create_witin(|| format!("{}_witness_high", name))
            })),
            _marker: std::marker::PhantomData,
        }
    }
}

impl<F: SmallField, P: FieldParameters + NumLimbs> CompactFieldRelationCols<F, P> {
    pub fn populate(
        &mut self,
        record: &mut LkMultiplicity,
        lhs: &Polynomial<F>,
        rhs: &Polynomial<F>,
        positive_modulus_offset: &BigUint,
        quotient: &BigUint,
    ) {
        let p_modulus: Polynomial<F> = P::to_limbs_field::<F, _>(&P::modulus()).into();
        let p_offset: Polynomial<F> =
            to_compact_relation_limbs_field::<F, _>(positive_modulus_offset).into();
        let p_quotient: Polynomial<F> = to_compact_relation_limbs_field::<F, _>(quotient).into();
        let p_vanishing = lhs + &(&p_offset * &p_modulus) - rhs - &(&p_quotient * &p_modulus);

        let p_witness = compute_root_quotient_and_shift(
            &p_vanishing,
            P::WITNESS_OFFSET,
            P::NB_BITS_PER_LIMB as u32,
            U63::USIZE,
        );
        let (p_witness_low, p_witness_high): (Vec<F>, Vec<F>) =
            split_u16_limbs_to_u8_limbs(&p_witness);

        self.quotient = p_quotient.into();
        self.witness_low = Limbs(p_witness_low.try_into().unwrap());
        self.witness_high = Limbs(p_witness_high.try_into().unwrap());

        record.assert_byte_fields(&self.quotient.0);
        record.assert_byte_fields(&self.witness_low.0);
        record.assert_byte_fields(&self.witness_high.0);
    }

    pub fn populate_with_evals(
        &mut self,
        record: &mut LkMultiplicity,
        lhs: &Polynomial<F>,
        rhs: &Polynomial<F>,
        positive_modulus_offset: &BigUint,
        lhs_eval: &BigUint,
        rhs_eval: &BigUint,
    ) {
        let modulus = P::modulus();
        let numerator = lhs_eval + positive_modulus_offset * &modulus - rhs_eval;
        debug_assert_eq!(&numerator % &modulus, BigUint::from(0u32));
        let quotient = numerator / &modulus;
        self.populate(record, lhs, rhs, positive_modulus_offset, &quotient);
    }
}

impl<Expr: Clone, P: FieldParameters + NumLimbs> CompactFieldRelationCols<Expr, P> {
    pub fn eval<E>(
        &self,
        builder: &mut CircuitBuilder<E>,
        lhs: &Polynomial<Expression<E>>,
        rhs: &Polynomial<Expression<E>>,
        positive_modulus_offset: &BigUint,
    ) -> Result<(), CircuitBuilderError>
    where
        E: ExtensionField,
        Expr: ToExpr<E, Output = Expression<E>>,
        Expression<E>: From<Expr>,
    {
        let p_limbs =
            Polynomial::from_iter(P::modulus_field_iter::<E::BaseField>().map(|x| x.expr()));
        let p_offset = to_compact_relation_limbs_expr::<E>(positive_modulus_offset);
        let p_offset: Polynomial<Expression<E>> = p_offset.into();
        let p_quotient: Polynomial<Expression<E>> = self.quotient.clone().into();
        let p_vanishing =
            lhs + &poly_mul_expr(&p_offset, &p_limbs) - rhs - &poly_mul_expr(&p_quotient, &p_limbs);

        let p_witness_low = self.witness_low.0.iter().into();
        let p_witness_high = self.witness_high.0.iter().into();
        eval_field_operation::<E, P>(builder, &p_vanishing, &p_witness_low, &p_witness_high)?;

        builder.assert_bytes(|| "compact relation quotient", &self.quotient.0)?;
        builder.assert_bytes(|| "compact relation witness_low", &self.witness_low.0)?;
        builder.assert_bytes(|| "compact relation witness_high", &self.witness_high.0)
    }
}
