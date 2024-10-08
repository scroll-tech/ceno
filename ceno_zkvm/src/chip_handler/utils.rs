use std::iter::successors;

use crate::expression::Expression;
use ff::Field;
use ff_ext::ExtensionField;

pub fn rlc_chip_record<E: ExtensionField>(
    records: Vec<Expression<E>>,
    chip_record_alpha: Expression<E>,
    chip_record_beta: Expression<E>,
) -> Expression<E> {
    assert!(!records.is_empty());
    let beta_pows = power_sequence(chip_record_beta, records.len());

    let item_rlc = beta_pows
        .into_iter()
        .zip(records.iter())
        .map(|(beta, record)| beta * record.clone())
        .reduce(|a, b| a + b)
        .expect("reduce error");

    item_rlc + chip_record_alpha.clone()
}

/// derive power sequence [1, base, base^2, ..., base^(len-1)] of base expression
pub fn power_sequence<E: ExtensionField>(base: Expression<E>, len: usize) -> Vec<Expression<E>> {
    assert!(
        matches!(
            base,
            Expression::Constant { .. } | Expression::Challenge { .. }
        ),
        "expression must be constant or challenge"
    );
    successors(Some(Expression::Constant(E::BaseField::ONE)), |prev| {
        Some(prev.clone() * base.clone())
    })
    .take(len)
    .collect()
}
