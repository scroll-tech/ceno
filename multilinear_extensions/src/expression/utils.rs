use ff_ext::ExtensionField;

use super::{Expression, StructuralWitIn, WitIn};

impl WitIn {
    pub fn assign<E: ExtensionField>(&self, instance: &mut [E::BaseField], value: E::BaseField) {
        instance[self.id as usize] = value;
    }
}

impl StructuralWitIn {
    pub fn assign<E: ExtensionField>(&self, instance: &mut [E::BaseField], value: E::BaseField) {
        instance[self.id as usize] = value;
    }
}

pub fn eval_by_expr<E: ExtensionField>(
    witnesses: &[E],
    structural_witnesses: &[E],
    challenges: &[E],
    expr: &Expression<E>,
) -> E {
    eval_by_expr_with_fixed(&[], witnesses, structural_witnesses, challenges, expr)
}

pub fn eval_by_expr_with_fixed<E: ExtensionField>(
    fixed: &[E],
    witnesses: &[E],
    structural_witnesses: &[E],
    challenges: &[E],
    expr: &Expression<E>,
) -> E {
    expr.evaluate::<E>(
        &|f| fixed[f.0],
        &|witness_id| witnesses[witness_id as usize],
        &|witness_id, _, _, _| structural_witnesses[witness_id as usize],
        &|scalar| scalar.into(),
        &|challenge_id, pow, scalar, offset| {
            // TODO cache challenge power to be acquired once for each power
            let challenge = challenges[challenge_id as usize];
            challenge.exp_u64(pow as u64) * scalar + offset
        },
        &|a, b| a + b,
        &|a, b| a * b,
        &|x, a, b| a * x + b,
    )
}

pub fn eval_by_expr_with_instance<E: ExtensionField>(
    fixed: &[E],
    witnesses: &[E],
    structural_witnesses: &[E],
    instance: &[E],
    challenges: &[E],
    expr: &Expression<E>,
) -> E {
    expr.evaluate_with_instance::<E>(
        &|f| fixed[f.0],
        &|witness_id| witnesses[witness_id as usize],
        &|witness_id, _, _, _| structural_witnesses[witness_id as usize],
        &|i| instance[i.0],
        &|scalar| scalar.into(),
        &|challenge_id, pow, scalar, offset| {
            // TODO cache challenge power to be acquired once for each power
            let challenge = challenges[challenge_id as usize];
            challenge.exp_u64(pow as u64) * scalar + offset
        },
        &|a, b| a + b,
        &|a, b| a * b,
        &|x, a, b| a * x + b,
    )
}
