use std::iter::successors;

use ff_ext::ExtensionField;
use itertools::izip;
use multilinear_extensions::{Expression, ToExpr};
use p3::field::FieldAlgebra;

pub fn rlc_chip_record<E: ExtensionField>(
    records: Vec<Expression<E>>,
    chip_record_alpha: Expression<E>,
    chip_record_beta: Expression<E>,
) -> Expression<E> {
    assert!(!records.is_empty());
    let beta_pows = power_sequence(chip_record_beta);

    let item_rlc = izip!(records, beta_pows)
        .map(|(record, beta)| record * beta)
        .sum::<Expression<E>>();

    item_rlc + chip_record_alpha.clone()
}

/// derive power sequence [1, base, base^2, ..., base^(len-1)] of base expression
pub fn power_sequence<E: ExtensionField>(
    base: Expression<E>,
) -> impl Iterator<Item = Expression<E>> {
    assert!(
        matches!(
            base,
            Expression::Constant { .. } | Expression::Challenge { .. }
        ),
        "expression must be constant or challenge"
    );
    successors(Some(E::BaseField::ONE.expr()), move |prev| {
        Some(prev.clone() * base.clone())
    })
}
