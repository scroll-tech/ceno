use std::collections::HashMap;

use goldilocks::SmallField;
use simple_frontend::structs::{ChallengeConst, ConstantType};

use crate::structs::{Gate1In, Gate2In, Gate3In, GateCIn};

mod circuit_layout;
mod circuit_witness;

pub trait EvaluateGateCIn<E>
where
    E: SmallField,
{
    fn eval(&self, out_eq_vec: &[E], challenges: &HashMap<ChallengeConst, Vec<E::BaseField>>) -> E;
    fn eval_subset_eq(&self, out_eq_vec: &[E], in_eq_vec: &[E]) -> E;
}

impl<E> EvaluateGateCIn<E> for &[GateCIn<ConstantType<E>>]
where
    E: SmallField,
{
    fn eval(&self, out_eq_vec: &[E], challenges: &HashMap<ChallengeConst, Vec<E::BaseField>>) -> E {
        self.iter().fold(E::ZERO, |acc, gate| {
            acc + out_eq_vec[gate.idx_out].mul_base(&gate.scalar.eval(challenges))
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
    E: SmallField,
{
    fn eval(
        &self,
        out_eq_vec: &[E],
        in_eq_vec: &[E],
        challenges: &HashMap<ChallengeConst, Vec<E::BaseField>>,
    ) -> E;
    fn fix_out_variables(
        &self,
        in_size: usize,
        out_eq_vec: &[E],
        challenges: &HashMap<ChallengeConst, Vec<E::BaseField>>,
    ) -> Vec<E>;
}

impl<E> EvaluateGate1In<E> for &[Gate1In<ConstantType<E>>]
where
    E: SmallField,
{
    fn eval(
        &self,
        out_eq_vec: &[E],
        in_eq_vec: &[E],
        challenges: &HashMap<ChallengeConst, Vec<E::BaseField>>,
    ) -> E {
        self.iter().fold(E::ZERO, |acc, gate| {
            acc + out_eq_vec[gate.idx_out]
                * in_eq_vec[gate.idx_in[0]].mul_base(&gate.scalar.eval(challenges))
        })
    }
    fn fix_out_variables(
        &self,
        in_size: usize,
        out_eq_vec: &[E],
        challenges: &HashMap<ChallengeConst, Vec<E::BaseField>>,
    ) -> Vec<E> {
        let mut ans = vec![E::ZERO; in_size];
        for gate in self.iter() {
            ans[gate.idx_in[0]] += out_eq_vec[gate.idx_out].mul_base(&gate.scalar.eval(challenges));
        }
        ans
    }
}

pub trait EvaluateGate2In<E>
where
    E: SmallField,
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
    E: SmallField,
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
                * in2_eq_vec[gate.idx_in[1]].mul_base(&gate.scalar.eval(&challenges))
        })
    }
}

pub trait EvaluateGate3In<E>
where
    E: SmallField,
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
    E: SmallField,
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
                * in3_eq_vec[gate.idx_in[2]].mul_base(&gate.scalar.eval(challenges))
        })
    }
}

pub(crate) trait EvaluateConstant<F: SmallField> {
    fn eval(&self, challenges: &HashMap<ChallengeConst, Vec<F::BaseField>>) -> F::BaseField;
}

impl<F: SmallField> EvaluateConstant<F> for ConstantType<F> {
    fn eval(&self, challenges: &HashMap<ChallengeConst, Vec<F::BaseField>>) -> F::BaseField {
        match self {
            ConstantType::Challenge(c, j) => challenges[&c][*j],
            ConstantType::ChallengeScaled(c, j, scalar) => challenges[&c][*j] * scalar,
            ConstantType::Field(c) => *c,
        }
    }
}
