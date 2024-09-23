use crate::expression::Expression;
use ff::Field;
use ff_ext::ExtensionField;

pub fn rlc_chip_record<E: ExtensionField>(
    records: Vec<Expression<E>>,
    chip_record_alpha: Expression<E>,
    chip_record_beta: Expression<E>,
) -> Expression<E> {
    assert!(!records.is_empty());
    let beta_pows = pows_expr(chip_record_beta, records.len());

    let item_rlc = beta_pows
        .into_iter()
        .zip(records.iter())
        .map(|(beta, record)| beta * record.clone())
        .reduce(|a, b| a + b)
        .expect("reduce error");

    item_rlc + chip_record_alpha.clone()
}

pub fn pows_expr<E: ExtensionField>(base: Expression<E>, len: usize) -> Vec<Expression<E>> {
    assert!(
        matches!(
            base,
            Expression::Constant { .. } | Expression::Challenge { .. }
        ),
        "expression must be constant or challenge"
    );
    let mut beta_pows = Vec::with_capacity(len);
    beta_pows.push(Expression::Constant(E::BaseField::ONE));
    if len > 0 {
        (0..len - 1).for_each(|_| beta_pows.push(base.clone() * beta_pows.last().unwrap().clone()));
    }
    beta_pows
}
