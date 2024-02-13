use goldilocks::SmallField;

use crate::structs::{Gate1In, Gate2In, Gate3In, GateCIn};

mod circuit_layout;
mod circuit_witness;

pub trait EvaluateGateCIn<F>
where
    F: SmallField,
{
    fn eval<E: SmallField<BaseField = F>>(&self, out: &[E]) -> E;
    fn eval_subset_eq<E: SmallField<BaseField = F>>(&self, out_eq_vec: &[E], in_eq_vec: &[E]) -> E;
}

impl<F> EvaluateGateCIn<F> for &[GateCIn<F>]
where
    F: SmallField,
{
    fn eval<E: SmallField<BaseField = F>>(&self, out_eq_vec: &[E]) -> E {
        self.iter().fold(E::ZERO, |acc, gate| {
            acc + out_eq_vec[gate.idx_out].mul_base(&gate.scalar)
        })
    }
    fn eval_subset_eq<E: SmallField<BaseField = F>>(&self, out_eq_vec: &[E], in_eq_vec: &[E]) -> E {
        self.iter().fold(E::ZERO, |acc, gate| {
            acc + out_eq_vec[gate.idx_out] * in_eq_vec[gate.idx_out]
        })
    }
}

pub trait EvaluateGate1In<F>
where
    F: SmallField,
{
    fn eval<E: SmallField<BaseField = F>>(&self, out_eq_vec: &[E], in_eq_vec: &[E]) -> E;
    fn fix_out_variables<E: SmallField<BaseField = F>>(
        &self,
        in_size: usize,
        out_eq_vec: &[E],
    ) -> Vec<E>;
}

impl<F> EvaluateGate1In<F> for &[Gate1In<F>]
where
    F: SmallField,
{
    fn eval<E: SmallField<BaseField = F>>(&self, out_eq_vec: &[E], in_eq_vec: &[E]) -> E {
        self.iter().fold(E::ZERO, |acc, gate| {
            acc + out_eq_vec[gate.idx_out] * in_eq_vec[gate.idx_in[0]].mul_base(&gate.scalar)
        })
    }
    fn fix_out_variables<E: SmallField<BaseField = F>>(
        &self,
        in_size: usize,
        out_eq_vec: &[E],
    ) -> Vec<E> {
        let mut ans = vec![E::ZERO; in_size];
        for gate in self.iter() {
            ans[gate.idx_in[0]] += out_eq_vec[gate.idx_out].mul_base(&gate.scalar);
        }
        ans
    }
}

pub trait EvaluateGate2In<F>
where
    F: SmallField,
{
    fn eval<E: SmallField<BaseField = F>>(
        &self,
        out_eq_vec: &[E],
        in1_eq_vec: &[E],
        in2_eq_vec: &[E],
    ) -> E;
}

impl<F> EvaluateGate2In<F> for &[Gate2In<F>]
where
    F: SmallField,
{
    fn eval<E: SmallField<BaseField = F>>(
        &self,
        out_eq_vec: &[E],
        in1_eq_vec: &[E],
        in2_eq_vec: &[E],
    ) -> E {
        self.iter().fold(E::ZERO, |acc, gate| {
            acc + out_eq_vec[gate.idx_out]
                * in1_eq_vec[gate.idx_in[0]]
                * in2_eq_vec[gate.idx_in[1]].mul_base(&gate.scalar)
        })
    }
}

pub trait EvaluateGate3In<F>
where
    F: SmallField,
{
    fn eval<E: SmallField<BaseField = F>>(
        &self,
        out_eq_vec: &[E],
        in1_eq_vec: &[E],
        in2_eq_vec: &[E],
        in3_eq_vec: &[E],
    ) -> E;
}

impl<F> EvaluateGate3In<F> for &[Gate3In<F>]
where
    F: SmallField,
{
    fn eval<E: SmallField<BaseField = F>>(
        &self,
        out_eq_vec: &[E],
        in1_eq_vec: &[E],
        in2_eq_vec: &[E],
        in3_eq_vec: &[E],
    ) -> E {
        self.iter().fold(E::ZERO, |acc, gate| {
            acc + out_eq_vec[gate.idx_out]
                * in1_eq_vec[gate.idx_in[0]]
                * in2_eq_vec[gate.idx_in[1]]
                * in3_eq_vec[gate.idx_in[2]].mul_base(&gate.scalar)
        })
    }
}
