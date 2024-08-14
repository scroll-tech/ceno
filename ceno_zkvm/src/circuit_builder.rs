use std::marker::PhantomData;

use ff_ext::ExtensionField;

use crate::{expression::Expression, structs::WitnessId};

#[derive(Clone, Debug)]
// TODO it's a bit weird for the circuit builder to be clonable. Might define a internal meta for it
// maybe we should move all of them to a meta object and make CircuitBuilder stateless.
pub struct CircuitBuilder<E: ExtensionField> {
    pub(crate) num_witin: WitnessId,
    pub r_expressions: Vec<Expression<E>>,
    pub w_expressions: Vec<Expression<E>>,
    /// lookup expression
    pub lk_expressions: Vec<Expression<E>>,

    /// main constraints zero expression
    pub assert_zero_expressions: Vec<Expression<E>>,
    /// main constraints zero expression for expression degree > 1, which require sumcheck to prove
    pub assert_zero_sumcheck_expressions: Vec<Expression<E>>,
    /// max zero sumcheck degree
    pub max_non_lc_degree: usize,

    // alpha, beta challenge for chip record
    pub chip_record_alpha: Expression<E>,
    pub chip_record_beta: Expression<E>,

    pub(crate) phantom: PhantomData<E>,
}

#[derive(Clone, Debug)]
pub struct Circuit<E: ExtensionField> {
    pub num_witin: WitnessId,
    pub r_expressions: Vec<Expression<E>>,
    pub w_expressions: Vec<Expression<E>>,
    /// lookup expression
    pub lk_expressions: Vec<Expression<E>>,

    /// main constraints zero expression
    pub assert_zero_expressions: Vec<Expression<E>>,
    /// main constraints zero expression for expression degree > 1, which require sumcheck to prove
    pub assert_zero_sumcheck_expressions: Vec<Expression<E>>,

    /// max zero sumcheck degree
    pub max_non_lc_degree: usize,
}
