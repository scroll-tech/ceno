use goldilocks::SmallField;

use crate::structs::{Gate1In, Gate2In, Gate3In, GateCIn};

mod circuit_layout;
mod circuit_witness;

pub trait EvaluateGateCIn<F>
where
    F: SmallField,
{
    fn eval(&self, out: &[F]) -> F;
    fn eval_subset_eq(&self, out_eq_vec: &[F], in_eq_vec: &[F]) -> F;
}

impl<F> EvaluateGateCIn<F> for &[GateCIn<F>]
where
    F: SmallField,
{
    fn eval(&self, out_eq_vec: &[F]) -> F {
        self.iter().fold(F::ZERO, |acc, gate| {
            acc + out_eq_vec[gate.idx_out] * gate.constant
        })
    }
    fn eval_subset_eq(&self, out_eq_vec: &[F], in_eq_vec: &[F]) -> F {
        self.iter().fold(F::ZERO, |acc, gate| {
            acc + out_eq_vec[gate.idx_out] * in_eq_vec[gate.idx_out]
        })
    }
}

pub trait EvaluateGate1In<F>
where
    F: SmallField,
{
    fn eval(&self, out_eq_vec: &[F], in_eq_vec: &[F]) -> F;
    fn fix_out_variables(&self, in_size: usize, out_eq_vec: &[F]) -> Vec<F>;
}

impl<F> EvaluateGate1In<F> for &[Gate1In<F>]
where
    F: SmallField,
{
    fn eval(&self, out_eq_vec: &[F], in_eq_vec: &[F]) -> F {
        self.iter().fold(F::ZERO, |acc, gate| {
            acc + out_eq_vec[gate.idx_out] * in_eq_vec[gate.idx_in] * gate.scaler
        })
    }
    fn fix_out_variables(&self, in_size: usize, out_eq_vec: &[F]) -> Vec<F> {
        let mut ans = vec![F::ZERO; in_size];
        for gate in self.iter() {
            ans[gate.idx_in] += out_eq_vec[gate.idx_out] * gate.scaler;
        }
        ans
    }
}

pub trait EvaluateGate2In<F>
where
    F: SmallField,
{
    fn eval(&self, out_eq_vec: &[F], in1_eq_vec: &[F], in2_eq_vec: &[F]) -> F;
}

impl<F> EvaluateGate2In<F> for &[Gate2In<F>]
where
    F: SmallField,
{
    fn eval(&self, out_eq_vec: &[F], in1_eq_vec: &[F], in2_eq_vec: &[F]) -> F {
        self.iter().fold(F::ZERO, |acc, gate| {
            acc + out_eq_vec[gate.idx_out]
                * in1_eq_vec[gate.idx_in1]
                * in2_eq_vec[gate.idx_in2]
                * gate.scaler
        })
    }
}

pub trait EvaluateGate3In<F>
where
    F: SmallField,
{
    fn eval(&self, out_eq_vec: &[F], in1_eq_vec: &[F], in2_eq_vec: &[F], in3_eq_vec: &[F]) -> F;
}

impl<F> EvaluateGate3In<F> for &[Gate3In<F>]
where
    F: SmallField,
{
    fn eval(&self, out_eq_vec: &[F], in1_eq_vec: &[F], in2_eq_vec: &[F], in3_eq_vec: &[F]) -> F {
        self.iter().fold(F::ZERO, |acc, gate| {
            acc + out_eq_vec[gate.idx_out]
                * in1_eq_vec[gate.idx_in1]
                * in2_eq_vec[gate.idx_in2]
                * in3_eq_vec[gate.idx_in3]
                * gate.scaler
        })
    }
}
