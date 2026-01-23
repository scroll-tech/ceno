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
    field::{Field, FieldAlgebra, PrimeField},
    monty_31::InternalLayerBaseParameters,
    poseidon2::{GenericPoseidon2LinearLayers, MDSMat4, mds_light_permutation},
    poseidon2_air::{FullRound, PartialRound, Poseidon2Cols, SBox, num_cols},
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

impl<F: Field, const WIDTH: usize, const HALF_FULL_ROUNDS: usize, const PARTIAL_ROUNDS: usize>
    From<Vec<F>> for RoundConstants<F, WIDTH, HALF_FULL_ROUNDS, PARTIAL_ROUNDS>
{
    fn from(value: Vec<F>) -> Self {
        let mut iter = value.into_iter();
        let mut beginning_full_round_constants = [[F::ZERO; WIDTH]; HALF_FULL_ROUNDS];

        beginning_full_round_constants.iter_mut().for_each(|arr| {
            arr.iter_mut()
                .for_each(|c| *c = iter.next().expect("insufficient round constants"))
        });

        let mut partial_round_constants = [F::ZERO; PARTIAL_ROUNDS];

        partial_round_constants
            .iter_mut()
            .for_each(|arr| *arr = iter.next().expect("insufficient round constants"));

        let mut ending_full_round_constants = [[F::ZERO; WIDTH]; HALF_FULL_ROUNDS];
        ending_full_round_constants.iter_mut().for_each(|arr| {
            arr.iter_mut()
                .for_each(|c| *c = iter.next().expect("insufficient round constants"))
        });

        assert!(iter.next().is_none(), "round constants are too many");

        RoundConstants {
            beginning_full_round_constants,
            partial_round_constants,
            ending_full_round_constants,
        }
    }
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
    p3_cols: Vec<WitIn>,                // columns in the plonky3-air
    post_linear_layer_cols: Vec<WitIn>, /* additional columns to hold the state after linear layers */
    constants: RoundConstants<E::BaseField, STATE_WIDTH, HALF_FULL_ROUNDS, PARTIAL_ROUNDS>,
}

#[derive(Debug, Clone)]
pub struct Poseidon2LinearLayers;

impl<F: Field, const WIDTH: usize> GenericPoseidon2LinearLayers<F, WIDTH>
    for Poseidon2LinearLayers
{
    fn internal_linear_layer(state: &mut [F; WIDTH]) {
        // this only works when F is BabyBear field for now
        let babybear_prime = BigUint::from(0x7800_0001u32);
        if F::order() == babybear_prime {
            let diag_m1_matrix = &<BabyBearInternalLayerParameters as InternalLayerBaseParameters<
            _,
            16,
        >>::INTERNAL_DIAG_MONTY;
            let diag_m1_matrix: &[F; WIDTH] = unsafe { transmute(diag_m1_matrix) };
            let sum = state.iter().cloned().sum::<F>();
            for (input, diag_m1) in state.iter_mut().zip(diag_m1_matrix) {
                *input = sum + F::from_f(*diag_m1) * *input;
            }
        } else {
            panic!("Unsupported field");
        }
    }

    fn external_linear_layer(state: &mut [F; WIDTH]) {
        mds_light_permutation(state, &MDSMat4);
    }
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
            cb.require_equal(|| "post_i = state_i", state_i.clone(), post_i.clone())?;
            *state_i = post_i.clone();
        }

        Ok(())
    }

    fn eval_partial_round(
        state: &mut [Expression<E>; STATE_WIDTH],
        post_linear_layer: &WitIn,
        partial_round: &PartialRound<Expression<E>, STATE_WIDTH, SBOX_DEGREE, SBOX_REGISTERS>,
        round_constant: &E::BaseField,
        cb: &mut CircuitBuilder<E>,
    ) -> Result<(), CircuitBuilderError> {
        cb.require_equal(
            || "post_linear_layer[0] = state[0]",
            post_linear_layer.expr(),
            state[0].clone() + round_constant.expr(),
        )?;
        state[0] = post_linear_layer.expr();

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
        let num_p3_cols =
            num_cols::<STATE_WIDTH, SBOX_DEGREE, SBOX_REGISTERS, HALF_FULL_ROUNDS, PARTIAL_ROUNDS>(
            );
        let p3_cols = from_fn(|| Some(cb.create_witin(|| "poseidon2 col")))
            .take(num_p3_cols)
            .collect::<Vec<_>>();
        let mut col_exprs = p3_cols
            .iter()
            .map(|c| c.expr())
            .collect::<Vec<Expression<E>>>();

        // allocate columns to cache the state after each linear layer
        // 1. before 0th full round
        let mut post_linear_layer_cols = (0..STATE_WIDTH)
            .map(|j| {
                cb.create_witin(|| format!("[before 0th full round] post linear layer col[{j}]"))
            })
            .collect::<Vec<WitIn>>();
        // 2. before each partial round
        for i in 0..PARTIAL_ROUNDS {
            post_linear_layer_cols.push(cb.create_witin(|| {
                format!("[round {}] post linear layer col", i + HALF_FULL_ROUNDS)
            }));
        }
        // 3. before HALF_FULL_ROUNDS-th full round
        post_linear_layer_cols.extend((0..STATE_WIDTH).map(|j| {
            cb.create_witin(|| {
                format!(
                    "[before {}th full round] post linear layer col[{j}]",
                    HALF_FULL_ROUNDS
                )
            })
        }));

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

        // after linear layer, each state_i has ~STATE_WIDTH terms
        // therefore, we want to reduce that to one as the number of terms
        // after sbox(state_i + rc_i) = (state_i + rc_i)^d will explode
        poseidon2_cols
            .inputs
            .iter_mut()
            .zip_eq(post_linear_layer_cols[0..STATE_WIDTH].iter())
            .for_each(|(input, post_linear)| {
                cb.require_equal(
                    || "post_linear_layer = input",
                    post_linear.expr(),
                    input.clone(),
                )
                .unwrap();
                *input = post_linear.expr();
            });

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
                &post_linear_layer_cols[STATE_WIDTH + round],
                &poseidon2_cols.partial_rounds[round],
                &round_constants.partial_round_constants[round],
                cb,
            )
            .unwrap();
        }

        poseidon2_cols
            .inputs
            .iter_mut()
            .zip_eq(post_linear_layer_cols[STATE_WIDTH + PARTIAL_ROUNDS..].iter())
            .for_each(|(input, post_linear)| {
                cb.require_equal(
                    || "post_linear_layer = input",
                    post_linear.expr(),
                    input.clone(),
                )
                .unwrap();
                *input = post_linear.expr();
            });

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
            p3_cols,
            post_linear_layer_cols,
            constants: round_constants,
        }
    }

    pub fn inputs(&self) -> Vec<Expression<E>> {
        let col_exprs = self.p3_cols.iter().map(|c| c.expr()).collect::<Vec<_>>();

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
        let col_exprs = self.p3_cols.iter().map(|c| c.expr()).collect::<Vec<_>>();

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

    fn num_p3_cols(&self) -> usize {
        self.p3_cols.len()
    }

    pub fn num_cols(&self) -> usize {
        self.p3_cols.len() + self.post_linear_layer_cols.len()
    }

    pub fn assign_instance(
        &self,
        instance: &mut [E::BaseField],
        state: [E::BaseField; STATE_WIDTH],
    ) {
        let (p3_cols, post_linear_layer_cols) = instance.split_at_mut(self.num_p3_cols());

        let poseidon2_cols: &mut Poseidon2Cols<
            E::BaseField,
            STATE_WIDTH,
            SBOX_DEGREE,
            SBOX_REGISTERS,
            HALF_FULL_ROUNDS,
            PARTIAL_ROUNDS,
        > = p3_cols.borrow_mut();

        generate_trace_rows_for_perm::<
            E::BaseField,
            Poseidon2LinearLayers,
            STATE_WIDTH,
            SBOX_DEGREE,
            SBOX_REGISTERS,
            HALF_FULL_ROUNDS,
            PARTIAL_ROUNDS,
        >(
            poseidon2_cols,
            post_linear_layer_cols,
            state,
            &self.constants,
        );
    }
}

//////////////////////////////////////////////////////////////////////////
/// The following routines are taken from poseidon2-air/src/generation.rs
//////////////////////////////////////////////////////////////////////////
fn generate_trace_rows_for_perm<
    F: PrimeField,
    LinearLayers: GenericPoseidon2LinearLayers<F, WIDTH>,
    const WIDTH: usize,
    const SBOX_DEGREE: u64,
    const SBOX_REGISTERS: usize,
    const HALF_FULL_ROUNDS: usize,
    const PARTIAL_ROUNDS: usize,
>(
    perm: &mut Poseidon2Cols<
        F,
        WIDTH,
        SBOX_DEGREE,
        SBOX_REGISTERS,
        HALF_FULL_ROUNDS,
        PARTIAL_ROUNDS,
    >,
    post_linear_layers: &mut [F],
    mut state: [F; WIDTH],
    constants: &RoundConstants<F, WIDTH, HALF_FULL_ROUNDS, PARTIAL_ROUNDS>,
) {
    perm.export = F::ONE;
    perm.inputs
        .iter_mut()
        .zip(state.iter())
        .for_each(|(input, &x)| {
            *input = x;
        });

    LinearLayers::external_linear_layer(&mut state);

    // 1. before 0th full round
    // post_linear_layer[i] = state[i]
    post_linear_layers[0..WIDTH]
        .iter_mut()
        .zip(state.iter())
        .for_each(|(post, &x)| {
            *post = x;
        });

    for (full_round, constants) in perm
        .beginning_full_rounds
        .iter_mut()
        .zip(&constants.beginning_full_round_constants)
    {
        generate_full_round::<F, LinearLayers, WIDTH, SBOX_DEGREE, SBOX_REGISTERS>(
            &mut state, full_round, constants,
        );
    }

    for (i, (partial_round, constant)) in perm
        .partial_rounds
        .iter_mut()
        .zip(&constants.partial_round_constants)
        .enumerate()
    {
        generate_partial_round::<F, LinearLayers, WIDTH, SBOX_DEGREE, SBOX_REGISTERS>(
            &mut state,
            &mut post_linear_layers[WIDTH + i],
            partial_round,
            *constant,
        );
    }

    // 3. before HALF_FULL_ROUNDS-th full round
    // post_linear_layer[i] = state[i]
    post_linear_layers[WIDTH + PARTIAL_ROUNDS..]
        .iter_mut()
        .zip(state.iter())
        .for_each(|(post, &x)| {
            *post = x;
        });

    for (full_round, constants) in perm
        .ending_full_rounds
        .iter_mut()
        .zip(&constants.ending_full_round_constants)
    {
        generate_full_round::<F, LinearLayers, WIDTH, SBOX_DEGREE, SBOX_REGISTERS>(
            &mut state, full_round, constants,
        );
    }
}

#[inline]
fn generate_full_round<
    F: PrimeField,
    LinearLayers: GenericPoseidon2LinearLayers<F, WIDTH>,
    const WIDTH: usize,
    const SBOX_DEGREE: u64,
    const SBOX_REGISTERS: usize,
>(
    state: &mut [F; WIDTH],
    full_round: &mut FullRound<F, WIDTH, SBOX_DEGREE, SBOX_REGISTERS>,
    round_constants: &[F; WIDTH],
) {
    for (state_i, const_i) in state.iter_mut().zip(round_constants) {
        *state_i += *const_i;
    }
    for (state_i, sbox_i) in state.iter_mut().zip(full_round.sbox.iter_mut()) {
        generate_sbox(sbox_i, state_i);
    }
    LinearLayers::external_linear_layer(state);
    full_round
        .post
        .iter_mut()
        .zip(*state)
        .for_each(|(post, x)| {
            *post = x;
        });
}

#[inline]
fn generate_partial_round<
    F: PrimeField,
    LinearLayers: GenericPoseidon2LinearLayers<F, WIDTH>,
    const WIDTH: usize,
    const SBOX_DEGREE: u64,
    const SBOX_REGISTERS: usize,
>(
    state: &mut [F; WIDTH],
    post_linear_layer: &mut F,
    partial_round: &mut PartialRound<F, WIDTH, SBOX_DEGREE, SBOX_REGISTERS>,
    round_constant: F,
) {
    state[0] += round_constant;
    *post_linear_layer = state[0];
    generate_sbox(&mut partial_round.sbox, &mut state[0]);
    partial_round.post_sbox = state[0];
    LinearLayers::internal_linear_layer(state);
}

#[inline]
fn generate_sbox<F: PrimeField, const DEGREE: u64, const REGISTERS: usize>(
    sbox: &mut SBox<F, DEGREE, REGISTERS>,
    x: &mut F,
) {
    *x = match (DEGREE, REGISTERS) {
        (3, 0) => x.cube(),
        (5, 0) => x.exp_const_u64::<5>(),
        (7, 0) => x.exp_const_u64::<7>(),
        (5, 1) => {
            let x2 = x.square();
            let x3 = x2 * *x;
            sbox.0[0] = x3;
            x3 * x2
        }
        (7, 1) => {
            let x3 = x.cube();
            sbox.0[0] = x3;
            x3 * x3 * *x
        }
        (11, 2) => {
            let x2 = x.square();
            let x3 = x2 * *x;
            let x9 = x3.cube();
            sbox.0[0] = x3;
            sbox.0[1] = x9;
            x9 * x2
        }
        _ => panic!(
            "Unexpected (DEGREE, REGISTERS) of ({}, {})",
            DEGREE, REGISTERS
        ),
    }
}

#[cfg(test)]
mod tests {
    use crate::gadgets::poseidon2::Poseidon2BabyBearConfig;
    use ff_ext::{BabyBearExt4, PoseidonField};
    use gkr_iop::circuit_builder::{CircuitBuilder, ConstraintSystem};
    use p3::babybear::BabyBear;

    type E = BabyBearExt4;
    type F = BabyBear;
    #[test]
    fn test_poseidon2_gadget() {
        let mut cs = ConstraintSystem::new(|| "poseidon2 gadget test");
        let mut cb = CircuitBuilder::<E>::new(&mut cs);

        // let poseidon2_constants = horizen_round_consts();
        let rc = <F as PoseidonField>::get_default_perm_rc().into();
        let _ = Poseidon2BabyBearConfig::construct(&mut cb, rc);
    }
}
