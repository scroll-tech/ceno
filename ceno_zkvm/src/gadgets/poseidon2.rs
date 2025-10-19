// Poseidon2 over BabyBear field

use std::{
    borrow::{Borrow, BorrowMut},
    iter::from_fn,
    mem::transmute,
};

use ff_ext::{BabyBearExt4, ExtensionField};
use gkr_iop::error::CircuitBuilderError;
use itertools::Itertools;
use multilinear_extensions::{Expression, ToExpr, WitIn};
use num_bigint::BigUint;
use p3::{
    babybear::BabyBearInternalLayerParameters,
    field::{Field, FieldAlgebra},
    monty_31::InternalLayerBaseParameters,
    poseidon2::{MDSMat4, mds_light_permutation},
    poseidon2_air::{FullRound, PartialRound, Poseidon2Cols, SBox, generate_trace_rows, num_cols},
};

use crate::circuit_builder::CircuitBuilder;

// copied from poseidon2-air/src/constants.rs
// as the original one cannot be accessed here
#[derive(Debug, Clone)]
pub struct RoundConstants<
    F: Field,
    const WIDTH: usize,
    const HALF_FULL_ROUNDS: usize,
    const PARTIAL_ROUNDS: usize,
> {
    pub beginning_full_round_constants: [[F; WIDTH]; HALF_FULL_ROUNDS],
    pub partial_round_constants: [F; PARTIAL_ROUNDS],
    pub ending_full_round_constants: [[F; WIDTH]; HALF_FULL_ROUNDS],
}

pub type Poseidon2BabyBearConfig = Poseidon2Config<BabyBearExt4, 16, 7, 1, 4, 13>;
pub struct Poseidon2Config<
    E: ExtensionField,
    const STATE_WIDTH: usize,
    const SBOX_DEGREE: u64,
    const SBOX_REGISTERS: usize,
    const HALF_FULL_ROUNDS: usize,
    const PARTIAL_ROUNDS: usize,
> {
    cols: Vec<WitIn>,
    constants: RoundConstants<E::BaseField, STATE_WIDTH, HALF_FULL_ROUNDS, PARTIAL_ROUNDS>,
}

impl<
    E: ExtensionField,
    const STATE_WIDTH: usize,
    const SBOX_DEGREE: u64,
    const SBOX_REGISTERS: usize,
    const HALF_FULL_ROUNDS: usize,
    const PARTIAL_ROUNDS: usize,
> Poseidon2Config<E, STATE_WIDTH, SBOX_DEGREE, SBOX_REGISTERS, HALF_FULL_ROUNDS, PARTIAL_ROUNDS>
{
    // constraints taken from poseidon2_air/src/air.rs
    fn eval_sbox(
        sbox: &SBox<Expression<E>, SBOX_DEGREE, SBOX_REGISTERS>,
        x: &mut Expression<E>,
        cb: &mut CircuitBuilder<E>,
    ) -> Result<(), CircuitBuilderError> {
        *x = match (SBOX_DEGREE, SBOX_REGISTERS) {
            (3, 0) => x.cube(),
            (5, 0) => x.exp_const_u64::<5>(),
            (7, 0) => x.exp_const_u64::<7>(),
            (5, 1) => {
                let committed_x3: Expression<E> = sbox.0[0].clone();
                let x2: Expression<E> = x.square();
                cb.require_zero(
                    || "x3 = x.cube()",
                    committed_x3.clone() - x2.clone() * x.clone(),
                )?;
                committed_x3 * x2
            }
            (7, 1) => {
                let committed_x3: Expression<E> = sbox.0[0].clone();
                // TODO: avoid x^3 as x may have ~STATE_WIDTH terms after the linear layer
                //       we can allocate one more column to store x^2 (which has ~STATE_WIDTH^2 terms)
                //       then x^3 = x * x^2
                //       but this will increase the number of columns (by FULL_ROUNDS * STATE_WIDTH + PARTIAL_ROUNDS)
                cb.require_zero(|| "x3 = x.cube()", committed_x3.clone() - x.cube())?;
                committed_x3.square() * x.clone()
            }
            _ => panic!(
                "Unexpected (SBOX_DEGREE, SBOX_REGISTERS) of ({}, {})",
                SBOX_DEGREE, SBOX_REGISTERS
            ),
        };

        Ok(())
    }

    fn eval_full_round(
        state: &mut [Expression<E>; STATE_WIDTH],
        full_round: &FullRound<Expression<E>, STATE_WIDTH, SBOX_DEGREE, SBOX_REGISTERS>,
        round_constants: &[E::BaseField],
        cb: &mut CircuitBuilder<E>,
    ) -> Result<(), CircuitBuilderError> {
        for (i, (s, r)) in state.iter_mut().zip_eq(round_constants.iter()).enumerate() {
            *s = s.clone() + r.expr();
            Self::eval_sbox(&full_round.sbox[i], s, cb)?;
        }
        Self::external_linear_layer(state);
        for (state_i, post_i) in state.iter_mut().zip_eq(full_round.post.iter()) {
            cb.require_zero(|| "post_i = state_i", state_i.clone() - post_i)?;
            *state_i = post_i.clone();
        }

        Ok(())
    }

    fn eval_partial_round(
        state: &mut [Expression<E>; STATE_WIDTH],
        partial_round: &PartialRound<Expression<E>, STATE_WIDTH, SBOX_DEGREE, SBOX_REGISTERS>,
        round_constant: &E::BaseField,
        cb: &mut CircuitBuilder<E>,
    ) -> Result<(), CircuitBuilderError> {
        state[0] = state[0].clone() + round_constant.expr();
        Self::eval_sbox(&partial_round.sbox, &mut state[0], cb)?;

        cb.require_zero(
            || "state[0] = post_sbox",
            state[0].clone() - partial_round.post_sbox.clone(),
        )?;
        state[0] = partial_round.post_sbox.clone();

        Self::internal_linear_layer(state);

        Ok(())
    }

    fn external_linear_layer(state: &mut [Expression<E>; STATE_WIDTH]) {
        mds_light_permutation(state, &MDSMat4);
    }

    fn internal_linear_layer(state: &mut [Expression<E>; STATE_WIDTH]) {
        let sum: Expression<E> = state.iter().map(|s| s.get_monomial_form()).sum();
        // reduce to monomial form
        let sum = sum.get_monomial_form();
        let babybear_prime = BigUint::from(0x7800_0001u32);
        if E::BaseField::order() == babybear_prime {
            // BabyBear
            let diag_m1_matrix_bb =
                &<BabyBearInternalLayerParameters as InternalLayerBaseParameters<_, 16>>::
                    INTERNAL_DIAG_MONTY;
            let diag_m1_matrix: &[E::BaseField; STATE_WIDTH] =
                unsafe { transmute(diag_m1_matrix_bb) };
            for (input, diag_m1) in state.iter_mut().zip_eq(diag_m1_matrix) {
                let updated = sum.clone() + Expression::from_f(*diag_m1) * input.clone();
                // reduce to monomial form
                *input = updated.get_monomial_form();
            }
        } else {
            panic!("Unsupported field");
        }
    }

    pub fn construct(
        cb: &mut CircuitBuilder<E>,
        round_constants: RoundConstants<
            E::BaseField,
            STATE_WIDTH,
            HALF_FULL_ROUNDS,
            PARTIAL_ROUNDS,
        >,
    ) -> Self {
        let num_cols =
            num_cols::<STATE_WIDTH, SBOX_DEGREE, SBOX_REGISTERS, HALF_FULL_ROUNDS, PARTIAL_ROUNDS>(
            );
        let cols = from_fn(|| Some(cb.create_witin(|| "poseidon2 col")))
            .take(num_cols)
            .collect::<Vec<_>>();
        let mut col_exprs = cols
            .iter()
            .map(|c| c.expr())
            .collect::<Vec<Expression<E>>>();

        let poseidon2_cols: &mut Poseidon2Cols<
            Expression<E>,
            STATE_WIDTH,
            SBOX_DEGREE,
            SBOX_REGISTERS,
            HALF_FULL_ROUNDS,
            PARTIAL_ROUNDS,
        > = col_exprs.as_mut_slice().borrow_mut();

        // external linear layer
        Self::external_linear_layer(&mut poseidon2_cols.inputs);

        // eval full round
        for round in 0..HALF_FULL_ROUNDS {
            Self::eval_full_round(
                &mut poseidon2_cols.inputs,
                &poseidon2_cols.beginning_full_rounds[round],
                &round_constants.beginning_full_round_constants[round],
                cb,
            )
            .unwrap();
        }

        // eval partial round
        for round in 0..PARTIAL_ROUNDS {
            Self::eval_partial_round(
                &mut poseidon2_cols.inputs,
                &poseidon2_cols.partial_rounds[round],
                &round_constants.partial_round_constants[round],
                cb,
            )
            .unwrap();
        }

        // TODO: after the last partial round, each state_i has ~STATE_WIDTH terms
        //       which will make the next full round to have many terms

        // eval full round
        for round in 0..HALF_FULL_ROUNDS {
            Self::eval_full_round(
                &mut poseidon2_cols.inputs,
                &poseidon2_cols.ending_full_rounds[round],
                &round_constants.ending_full_round_constants[round],
                cb,
            )
            .unwrap();
        }

        Poseidon2Config {
            cols,
            constants: round_constants,
        }
    }

    pub fn inputs(&self) -> Vec<Expression<E>> {
        let col_exprs = self.cols.iter().map(|c| c.expr()).collect::<Vec<_>>();

        let poseidon2_cols: &Poseidon2Cols<
            Expression<E>,
            STATE_WIDTH,
            SBOX_DEGREE,
            SBOX_REGISTERS,
            HALF_FULL_ROUNDS,
            PARTIAL_ROUNDS,
        > = col_exprs.as_slice().borrow();

        poseidon2_cols.inputs.to_vec()
    }

    pub fn output(&self) -> Vec<Expression<E>> {
        let col_exprs = self.cols.iter().map(|c| c.expr()).collect::<Vec<_>>();

        let poseidon2_cols: &Poseidon2Cols<
            Expression<E>,
            STATE_WIDTH,
            SBOX_DEGREE,
            SBOX_REGISTERS,
            HALF_FULL_ROUNDS,
            PARTIAL_ROUNDS,
        > = col_exprs.as_slice().borrow();

        poseidon2_cols
            .ending_full_rounds
            .last()
            .map(|r| r.post.to_vec())
            .unwrap()
    }

    // pub fn assign_instance(&self, input: &[E; STATE_WIDTH]) {
    //     generate_trace_rows(inputs, constants)
    //     let poseidon2_cols: &Poseidon2Cols<
    //         WitIn,
    //         STATE_WIDTH,
    //         SBOX_DEGREE,
    //         SBOX_REGISTERS,
    //         HALF_FULL_ROUNDS,
    //         PARTIAL_ROUNDS,
    //     > = self.cols.as_slice().borrow();
    // }
}

#[cfg(test)]
mod tests {
    use crate::gadgets::{
        poseidon2::Poseidon2BabyBearConfig, poseidon2_constants::horizen_round_consts,
    };
    use ff_ext::BabyBearExt4;
    use gkr_iop::circuit_builder::{CircuitBuilder, ConstraintSystem};

    type E = BabyBearExt4;
    #[test]
    fn test_poseidon2_gadget() {
        let mut cs = ConstraintSystem::new(|| "poseidon2 gadget test");
        let mut cb = CircuitBuilder::<E>::new(&mut cs);

        let poseidon2_constants = horizen_round_consts();
        let poseidon2_config = Poseidon2BabyBearConfig::construct(&mut cb, poseidon2_constants);
    }
}
