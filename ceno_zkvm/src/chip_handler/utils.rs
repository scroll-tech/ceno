use crate::expression::Expression;
use ff::Field;
use ff_ext::ExtensionField;

pub fn rlc_chip_record<E: ExtensionField>(
    records: Vec<Expression<E>>,
    chip_record_alpha: Expression<E>,
    chip_record_beta: Expression<E>,
) -> Expression<E> {
    assert!(!records.is_empty());
    let beta_pows = {
        let mut beta_pows = Vec::with_capacity(records.len());
        beta_pows.push(Expression::Constant(E::BaseField::ONE));
        (0..records.len() - 1).for_each(|_| {
            beta_pows.push(chip_record_beta.clone() * beta_pows.last().unwrap().clone())
        });
        beta_pows
    };

    let item_rlc = beta_pows
        .into_iter()
        .zip(records.iter())
        .map(|(beta, record)| beta * record.clone())
        .reduce(|a, b| a + b)
        .expect("reduce error");

    item_rlc + chip_record_alpha.clone()
}
