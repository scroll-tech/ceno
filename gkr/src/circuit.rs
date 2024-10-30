use std::collections::HashMap;

use ff_ext::ExtensionField;
use simple_frontend::structs::{ChallengeConst, ConstantType};

use crate::structs::{Gate1In, Gate2In, Gate3In, GateCIn};

mod circuit_layout;
mod circuit_witness;

pub trait EvaluateGateCIn<E>
where
    E: ExtensionField,
{
    fn eval(&self, out_eq_vec: &[E], challenges: &HashMap<ChallengeConst, Vec<E::BaseField>>) -> E;
    fn eval_subset_eq(&self, out_eq_vec: &[E], in_eq_vec: &[E]) -> E;
}

impl<E> EvaluateGateCIn<E> for &[GateCIn<ConstantType<E>>]
where
    E: ExtensionField,
{
    fn eval(&self, out_eq_vec: &[E], challenges: &HashMap<ChallengeConst, Vec<E::BaseField>>) -> E {
        self.iter().fold(E::ZERO, |acc, gate| {
            acc + out_eq_vec[gate.idx_out] * gate.scalar.eval(challenges)
        })
    }
    fn eval_subset_eq(&self, out_eq_vec: &[E], in_eq_vec: &[E]) -> E {
        self.iter().fold(E::ZERO, |acc, gate| {
            acc + out_eq_vec[gate.idx_out] * in_eq_vec[gate.idx_out]
        })
    }
}

pub trait EvaluateGate1In<E>
where
    E: ExtensionField,
{
    fn eval(
        &self,
        out_eq_vec: &[E],
        in_eq_vec: &[E],
        challenges: &HashMap<ChallengeConst, Vec<E::BaseField>>,
    ) -> E;
}

impl<E> EvaluateGate1In<E> for &[Gate1In<ConstantType<E>>]
where
    E: ExtensionField,
{
    fn eval(
        &self,
        out_eq_vec: &[E],
        in_eq_vec: &[E],
        challenges: &HashMap<ChallengeConst, Vec<E::BaseField>>,
    ) -> E {
        self.iter().fold(E::ZERO, |acc, gate| {
            acc + out_eq_vec[gate.idx_out]
                * in_eq_vec[gate.idx_in[0]]
                * gate.scalar.eval(challenges)
        })
    }
}

pub trait EvaluateGate2In<E>
where
    E: ExtensionField,
{
    fn eval(
        &self,
        out_eq_vec: &[E],
        in1_eq_vec: &[E],
        in2_eq_vec: &[E],
        challenges: &HashMap<ChallengeConst, Vec<E::BaseField>>,
    ) -> E;
}

impl<E> EvaluateGate2In<E> for &[Gate2In<ConstantType<E>>]
where
    E: ExtensionField,
{
    fn eval(
        &self,
        out_eq_vec: &[E],
        in1_eq_vec: &[E],
        in2_eq_vec: &[E],
        challenges: &HashMap<ChallengeConst, Vec<E::BaseField>>,
    ) -> E {
        self.iter().fold(E::ZERO, |acc, gate| {
            acc + out_eq_vec[gate.idx_out]
                * in1_eq_vec[gate.idx_in[0]]
                * in2_eq_vec[gate.idx_in[1]]
                * gate.scalar.eval(challenges)
        })
    }
}

pub trait EvaluateGate3In<E>
where
    E: ExtensionField,
{
    fn eval(
        &self,
        out_eq_vec: &[E],
        in1_eq_vec: &[E],
        in2_eq_vec: &[E],
        in3_eq_vec: &[E],
        challenges: &HashMap<ChallengeConst, Vec<E::BaseField>>,
    ) -> E;
}

impl<E> EvaluateGate3In<E> for &[Gate3In<ConstantType<E>>]
where
    E: ExtensionField,
{
    fn eval(
        &self,
        out_eq_vec: &[E],
        in1_eq_vec: &[E],
        in2_eq_vec: &[E],
        in3_eq_vec: &[E],
        challenges: &HashMap<ChallengeConst, Vec<E::BaseField>>,
    ) -> E {
        self.iter().fold(E::ZERO, |acc, gate| {
            acc + out_eq_vec[gate.idx_out]
                * in1_eq_vec[gate.idx_in[0]]
                * in2_eq_vec[gate.idx_in[1]]
                * in3_eq_vec[gate.idx_in[2]]
                * gate.scalar.eval(challenges)
        })
    }
}

pub(crate) trait EvaluateConstant<E: ExtensionField> {
    fn eval(&self, challenges: &HashMap<ChallengeConst, Vec<E::BaseField>>) -> E::BaseField;
}

impl<E: ExtensionField> EvaluateConstant<E> for ConstantType<E> {
    #[inline(always)]
    fn eval(&self, challenges: &HashMap<ChallengeConst, Vec<E::BaseField>>) -> E::BaseField {
        match self {
            ConstantType::Challenge(c, j) => challenges[c][*j],
            ConstantType::ChallengeScaled(c, j, scalar) => *scalar * challenges[c][*j],
            ConstantType::Field(c) => *c,
        }
    }
}
