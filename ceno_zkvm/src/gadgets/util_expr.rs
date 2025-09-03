use ff_ext::ExtensionField;
use gkr_iop::{circuit_builder::CircuitBuilder, error::CircuitBuilderError};
use multilinear_extensions::{Expression, ToExpr};
use p3_field::FieldAlgebra;
use sp1_curves::params::FieldParameters;

use sp1_curves::polynomial::Polynomial;

pub fn eval_field_operation<E: ExtensionField, P: FieldParameters>(
    builder: &mut CircuitBuilder<E>,
    p_vanishing: &Polynomial<Expression<E>>,
    p_witness_low: &Polynomial<Expression<E>>,
    p_witness_high: &Polynomial<Expression<E>>,
) -> Result<(), CircuitBuilderError> {
    // Reconstruct and shift back the witness polynomial
    let limb: Expression<E> =
        E::BaseField::from_canonical_u32(2u32.pow(P::NB_BITS_PER_LIMB as u32)).expr();

    let p_witness_shifted = p_witness_low + &(p_witness_high * limb.clone());

    // Shift down the witness polynomial. Shifting is needed to range check that each
    // coefficient w_i of the witness polynomial satisfies |w_i| < 2^WITNESS_OFFSET.
    let offset: Expression<E> = E::BaseField::from_canonical_u32(P::WITNESS_OFFSET as u32).expr();
    let len = p_witness_shifted.coefficients().len();
    let p_witness = p_witness_shifted - Polynomial::new(vec![offset; len]);

    // Multiply by (x-2^NB_BITS_PER_LIMB) and make the constraint
    let root_monomial = Polynomial::new(vec![-limb, E::BaseField::ONE.expr()]);

    let constraints = p_vanishing - &(p_witness * root_monomial);
    for constr in constraints.as_coefficients() {
        builder.require_zero(|| "eval_field_operation require zero", constr)?;
    }
    Ok(())
}
