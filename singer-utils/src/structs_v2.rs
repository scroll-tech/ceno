use std::marker::PhantomData;

use ff_ext::ExtensionField;
use simple_frontend::structs::WitnessId;

use crate::util_v2::ExpressionV2;

#[derive(Clone, Debug)]
// TODO it's a bit weird for the circuit builder to be clonable. Might define a internal meta for it
// maybe we should move all of them to a meta object and make CircuitBuilder stateless.
pub struct CircuitBuilderV2<E: ExtensionField> {
    pub(crate) num_witin: WitnessId,
    pub r_expressions: Vec<ExpressionV2<E>>,
    pub w_expressions: Vec<ExpressionV2<E>>,
    /// lookup expression
    pub lk_expressions: Vec<ExpressionV2<E>>,

    /// main constraints zero expression
    pub assert_zero_expressions: Vec<ExpressionV2<E>>,
    /// main constraints zero expression for expression degree > 1, which require sumcheck to prove
    pub assert_zero_sumcheck_expressions: Vec<ExpressionV2<E>>,

    // alpha, beta challenge for chip record
    pub chip_record_alpha: ExpressionV2<E>,
    pub chip_record_beta: ExpressionV2<E>,

    pub(crate) phantom: PhantomData<E>,
}

pub struct Circuit<E: ExtensionField> {
    pub num_witin: WitnessId,
    pub r_expressions: Vec<ExpressionV2<E>>,
    pub w_expressions: Vec<ExpressionV2<E>>,
    /// lookup expression
    pub lk_expressions: Vec<ExpressionV2<E>>,

    /// main constraints zero expression
    pub assert_zero_expressions: Vec<ExpressionV2<E>>,
    /// main constraints zero expression for expression degree > 1, which require sumcheck to prove
    pub assert_zero_sumcheck_expressions: Vec<ExpressionV2<E>>,
}
