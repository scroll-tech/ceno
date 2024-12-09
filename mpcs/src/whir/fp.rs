use std::marker::PhantomData;

use ark_ff::{BigInt, Fp2Config, FpConfig, QuadExtConfig};
use ff::{Field, PrimeField};
use ff_ext::ExtensionField;
use goldilocks::SmallField;

pub struct FpConfigBaseFieldOf<E: ExtensionField>(PhantomData<E>);

pub struct QuadExtConfigOf<E: ExtensionField>(PhantomData<E>);

/// In `ceno-goldilocks`, it is assumed that the small field does not have
/// more than 64 bits. So `N` is 1.
impl<E: ExtensionField> FpConfig<1> for FpConfigBaseFieldOf<E> {
    const MODULUS: BigInt<1> = BigInt::new([<E::BaseField as SmallField>::MODULUS_U64]);

    const GENERATOR: ark_ff::Fp<Self, 1> = ark_ff::Fp::<Self, 1>(
        BigInt::<1>::new([<E::BaseField as PrimeField>::MULTIPLICATIVE_GENERATOR]),
        PhantomData,
    );

    const ZERO: ark_ff::Fp<Self, 1> = ark_ff::Fp::<Self, 1>(BigInt::<1>::new([0]), PhantomData);

    const ONE: ark_ff::Fp<Self, 1> = ark_ff::Fp::<Self, 1>(BigInt::<1>::new([1]), PhantomData);

    const TWO_ADICITY: u32 = <E::BaseField as PrimeField>::S;

    const TWO_ADIC_ROOT_OF_UNITY: ark_ff::Fp<Self, 1> = ark_ff::Fp::<Self, 1>(
        BigInt::<1>::new(<E::BaseField as PrimeField>::ROOT_OF_UNITY),
        PhantomData,
    );

    // TODO: Does ff provides the same thing? If so, we can use it.
    const SQRT_PRECOMP: Option<ark_ff::SqrtPrecomputation<ark_ff::Fp<Self, 1>>> = None;

    fn add_assign(a: &mut ark_ff::Fp<Self, 1>, b: &ark_ff::Fp<Self, 1>) {
        todo!()
    }

    fn sub_assign(a: &mut ark_ff::Fp<Self, 1>, b: &ark_ff::Fp<Self, 1>) {
        todo!()
    }

    fn double_in_place(a: &mut ark_ff::Fp<Self, 1>) {
        todo!()
    }

    fn neg_in_place(a: &mut ark_ff::Fp<Self, 1>) {
        todo!()
    }

    fn mul_assign(a: &mut ark_ff::Fp<Self, 1>, b: &ark_ff::Fp<Self, 1>) {
        todo!()
    }

    fn sum_of_products<const T: usize>(
        a: &[ark_ff::Fp<Self, 1>; T],
        b: &[ark_ff::Fp<Self, 1>; T],
    ) -> ark_ff::Fp<Self, 1> {
        todo!()
    }

    fn square_in_place(a: &mut ark_ff::Fp<Self, 1>) {
        todo!()
    }

    fn inverse(a: &ark_ff::Fp<Self, 1>) -> Option<ark_ff::Fp<Self, 1>> {
        todo!()
    }

    fn from_bigint(other: ark_ff::BigInt<1>) -> Option<ark_ff::Fp<Self, 1>> {
        todo!()
    }

    fn into_bigint(other: ark_ff::Fp<Self, 1>) -> ark_ff::BigInt<1> {
        todo!()
    }
}

impl<E: ExtensionField> QuadExtConfig for QuadExtConfigOf<E> {
    type BasePrimeField = ark_ff::Fp<FpConfigBaseFieldOf<E>, 1>;

    type BaseField = Self::BasePrimeField;

    type FrobCoeff;

    const DEGREE_OVER_BASE_PRIME_FIELD: usize;

    const NONRESIDUE: Self::BaseField;

    const FROBENIUS_COEFF_C1: &'static [Self::FrobCoeff];

    fn mul_base_field_by_frob_coeff(fe: &mut Self::BaseField, power: usize) {
        todo!()
    }
}
