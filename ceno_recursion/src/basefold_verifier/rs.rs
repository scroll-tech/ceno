// Note: check all XXX comments!

use std::{cell::RefCell, collections::BTreeMap};

use openvm_native_compiler::{asm::AsmConfig, prelude::*};
use openvm_native_recursion::hints::Hintable;
use openvm_stark_sdk::p3_baby_bear::BabyBear;
use p3::field::{FieldAlgebra, extension::BinomialExtensionField};
use serde::Deserialize;

use super::{structs::*, utils::pow_felt_bits};

pub type F = BabyBear;
pub type E = BinomialExtensionField<F, DEGREE>;
pub type InnerConfig = AsmConfig<F, E>;

pub struct DenseMatrix {
    pub values: Vec<E>,
    pub width: usize,
}

impl Hintable<InnerConfig> for DenseMatrix {
    type HintVariable = DenseMatrixVariable<InnerConfig>;

    fn read(builder: &mut Builder<InnerConfig>) -> Self::HintVariable {
        let values = Vec::<E>::read(builder);
        let width = usize::read(builder);

        DenseMatrixVariable { values, width }
    }

    fn write(&self) -> Vec<Vec<<InnerConfig as Config>::N>> {
        let mut stream = Vec::new();
        stream.extend(self.values.write());
        stream.extend(<usize as Hintable<InnerConfig>>::write(&self.width));
        stream
    }
}

#[derive(DslVariable, Clone)]
pub struct DenseMatrixVariable<C: Config> {
    pub values: Array<C, Ext<C::F, C::EF>>,
    pub width: Var<C::N>,
}
pub type RowMajorMatrixVariable<C> = DenseMatrixVariable<C>;

impl<C: Config> DenseMatrixVariable<C> {
    pub fn height(&self, builder: &mut Builder<C>) -> Var<C::N> {
        // Supply height as hint
        let height = builder.hint_var();
        builder
            .if_eq(self.width.clone(), Usize::from(0))
            .then(|builder| {
                builder.assert_usize_eq(height, Usize::from(0));
            });
        builder
            .if_ne(self.width.clone(), Usize::from(0))
            .then(|builder| {
                // XXX: check that width * height is not a field multiplication
                builder.assert_usize_eq(self.width.clone() * height, self.values.len());
            });
        height
    }

    // XXX: Find better ways to handle this without cloning
    pub fn pad_to_height(
        &self,
        builder: &mut Builder<C>,
        new_height: Var<C::N>,
        fill: Ext<C::F, C::EF>,
    ) {
        // XXX: Not necessary, only for testing purpose
        let old_height = self.height(builder);
        builder.assert_less_than_slow_small_rhs(old_height, new_height + RVar::from(1));
        let new_size = builder.eval_expr(self.width.clone() * new_height.clone());
        let evals: Array<C, Ext<C::F, C::EF>> = builder.dyn_array(new_size);
        builder
            .range(0, self.values.len())
            .for_each(|i_vec, builder| {
                let i = i_vec[0];
                let tmp: Ext<C::F, C::EF> = builder.get(&self.values, i);
                builder.set(&evals, i, tmp);
            });
        builder
            .range(self.values.len(), evals.len())
            .for_each(|i_vec, builder| {
                let i = i_vec[0];
                builder.set(&evals, i, fill);
            });
        builder.assign(&self.values, evals);
    }
}

pub fn get_rate_log() -> usize {
    1
}

pub fn get_basecode_msg_size_log() -> usize {
    0
}

pub fn get_num_queries() -> usize {
    100
}

pub fn verifier_folding_coeffs_level<C: Config>(
    builder: &mut Builder<C>,
    two_adic_generators_inverses: &Array<C, Felt<C::F>>,
    level: Var<C::N>,
    index_bits: &Array<C, Var<C::N>>,
    two_inv: Felt<C::F>,
) -> Felt<C::F> {
    let level_plus_one = builder.eval::<Var<C::N>, _>(level + C::N::ONE);
    let g_inv = builder.get(two_adic_generators_inverses, level_plus_one);
    let g_inv_index = pow_felt_bits(builder, g_inv, index_bits, level.into());

    builder.eval(g_inv_index * two_inv)
}

/// The DIT FFT algorithm.
#[derive(Deserialize)]
pub struct Radix2Dit {
    pub twiddles: RefCell<BTreeMap<usize, Vec<F>>>,
}

impl Hintable<InnerConfig> for Radix2Dit {
    type HintVariable = Radix2DitVariable<InnerConfig>;

    fn read(builder: &mut Builder<InnerConfig>) -> Self::HintVariable {
        let twiddles = Vec::<E>::read(builder);

        Radix2DitVariable { twiddles }
    }

    fn write(&self) -> Vec<Vec<<InnerConfig as Config>::N>> {
        let mut stream = Vec::new();
        // XXX: process BTreeMap
        let twiddles_vec: Vec<E> = Vec::new();
        stream.extend(twiddles_vec.write());
        stream
    }
}

#[derive(DslVariable, Clone)]
pub struct Radix2DitVariable<C: Config> {
    /// Memoized twiddle factors for each length log_n.
    /// Precise definition is a map from usize to E
    pub twiddles: Array<C, Ext<C::F, C::EF>>,
}

// impl<C: Config> Radix2DitVariable<C> {
// fn dft_batch(
// &self,
// builder: &mut Builder<C>,
// mat: RowMajorMatrixVariable<C>
// ) -> RowMajorMatrixVariable<C> {
// let h = mat.height(builder);
// let log_h = builder.hint_var();
// let log_h_minus_1: Var<C::N> = builder.eval(log_h - Usize::from(1));
// let purported_h_lower_bound = pow_2(builder, log_h_minus_1);
// let purported_h_upper_bound = pow_2(builder, log_h);
// builder.assert_less_than_slow_small_rhs(purported_h_lower_bound, h);
// builder.assert_less_than_slow_small_rhs(h, purported_h_upper_bound);
//
// TODO: support memoization
// Compute twiddle factors, or take memoized ones if already available.
// let twiddles = {
// let root = F::two_adic_generator(log_h);
// root.powers().take(1 << log_h).collect()
// };
//
// DIT butterfly
// reverse_matrix_index_bits(&mut mat);
// for layer in 0..log_h {
// dit_layer(&mut mat.as_view_mut(), layer, twiddles);
// }
// mat
// }
// }

#[derive(Deserialize)]
pub struct RSCodeVerifierParameters {
    pub full_message_size_log: usize,
}

#[derive(DslVariable, Clone)]
pub struct RSCodeVerifierParametersVariable<C: Config> {
    pub full_message_size_log: Usize<C::N>,
}

// pub(crate) fn encode_small<C: Config>(
// builder: &mut Builder<C>,
// vp: RSCodeVerifierParametersVariable<C>,
// rmm: RowMajorMatrixVariable<C>,
// ) -> RowMajorMatrixVariable<C> {
// let m = rmm;
// Add current setup this is unnecessary
// let old_height = m.height(builder);
// let new_height = builder.eval_expr(
// old_height * Usize::from(1 << get_rate_log())
// );
// m.pad_to_height(builder, new_height, Ext::new(0));
// m
// }

/// Encode the last message sent from the prover to the verifier
/// in the commit phase. Currently, for simplicity, we drop the
/// early stopping strategy so the last message has just one
/// element, and the encoding is simply repeating this element
/// by the expansion rate.
pub(crate) fn encode_small<C: Config>(
    builder: &mut Builder<C>,
    rmm: RowMajorMatrixVariable<C>, // Assumed to have only one row and one column
) -> RowMajorMatrixVariable<C> {
    // XXX: nondeterministically supply the results for now
    let result = builder.array(2); // Assume the expansion rate is fixed to 2 by now
    let value = builder.get(&rmm.values, 0);
    builder.range(0, 2).for_each(|i_vec, builder| {
        let i = i_vec[0];
        builder.set_value(&result, i, value);
    });
    DenseMatrixVariable {
        values: result,
        width: builder.eval(Usize::from(1)),
    }
}

pub mod tests {
    use openvm_circuit::arch::{SystemConfig, VmExecutor, instructions::program::Program};
    use openvm_native_circuit::{Native, NativeConfig};
    use openvm_native_compiler::{asm::AsmBuilder, prelude::*};
    use openvm_native_recursion::hints::Hintable;
    use openvm_stark_backend::config::StarkGenericConfig;
    use openvm_stark_sdk::{
        config::baby_bear_poseidon2::BabyBearPoseidon2Config, p3_baby_bear::BabyBear,
    };
    use p3::field::{FieldAlgebra, extension::BinomialExtensionField};
    type SC = BabyBearPoseidon2Config;

    type F = BabyBear;
    type E = BinomialExtensionField<F, 4>;
    type EF = <SC as StarkGenericConfig>::Challenge;
    use super::{DenseMatrix, InnerConfig};

    #[allow(dead_code)]
    pub fn build_test_dense_matrix_pad() -> (Program<BabyBear>, Vec<Vec<BabyBear>>) {
        // OpenVM DSL
        let mut builder = AsmBuilder::<F, EF>::default();

        // Witness inputs
        let dense_matrix_variable = DenseMatrix::read(&mut builder);
        let new_height = builder.eval(Usize::from(8));
        let fill = Ext::new(0);
        dense_matrix_variable.pad_to_height(&mut builder, new_height, fill);
        builder.halt();

        // Pass in witness stream
        let mut witness_stream: Vec<
            Vec<p3_monty_31::MontyField31<openvm_stark_sdk::p3_baby_bear::BabyBearParameters>>,
        > = Vec::new();

        let verifier_input = DenseMatrix {
            values: vec![E::ONE; 25],
            width: 5,
        };
        witness_stream.extend(verifier_input.write());
        // Hint for height
        witness_stream.extend(<usize as Hintable<InnerConfig>>::write(&5));

        let program: Program<
            p3_monty_31::MontyField31<openvm_stark_sdk::p3_baby_bear::BabyBearParameters>,
        > = builder.compile_isa();

        (program, witness_stream)
    }

    #[test]
    fn test_dense_matrix_pad() {
        let (program, witness) = build_test_dense_matrix_pad();

        let system_config = SystemConfig::default()
            .with_public_values(4)
            .with_max_segment_len((1 << 25) - 100);
        let config = NativeConfig::new(system_config, Native);

        let executor = VmExecutor::<BabyBear, NativeConfig>::new(config);
        executor.execute(program, witness).unwrap();

        // _debug
        // let results = executor.execute_segments(program, witness).unwrap();
        // for seg in results {
        //     println!("=> cycle count: {:?}", seg.metrics.cycle_count);
        // }
    }
}
