use ff_ext::{BabyBearExt4, ExtensionField as CenoExtensionField, SmallField};
use openvm_native_compiler::prelude::*;
use openvm_native_recursion::challenger::{
    CanObserveVariable, CanSampleBitsVariable, duplex::DuplexChallengerVariable,
};
use openvm_stark_backend::p3_field::FieldAlgebra;

use crate::arithmetics::challenger_multi_observe;

pub fn transcript_observe_label<C: Config>(
    builder: &mut Builder<C>,
    challenger: &mut DuplexChallengerVariable<C>,
    label: &[u8],
) {
    let label_f = <BabyBearExt4 as CenoExtensionField>::BaseField::bytes_to_field_elements(label);
    for n in label_f {
        let f: Felt<C::F> = builder.constant(C::F::from_canonical_u64(n.to_canonical_u64()));
        challenger.observe(builder, f);
    }
}

pub fn transcript_label_as_array<C: Config>(
    builder: &mut Builder<C>,
    label: &[u8],
) -> Array<C, Felt<C::F>> {
    let label_f = <BabyBearExt4 as CenoExtensionField>::BaseField::bytes_to_field_elements(label);
    let arr: Array<C, Felt<C::F>> = builder.dyn_array(label_f.len());
    for (idx, n) in label_f.into_iter().enumerate() {
        let f: Felt<C::F> = builder.constant(C::F::from_canonical_u64(n.to_canonical_u64()));
        builder.set_value(&arr, idx, f);
    }
    arr
}

pub fn transcript_observe_label_felts<C: Config>(
    builder: &mut Builder<C>,
    challenger: &mut DuplexChallengerVariable<C>,
    label_felts: &Array<C, Felt<C::F>>,
) {
    challenger_multi_observe(builder, challenger, label_felts);
}

pub fn transcript_check_pow_witness<C: Config>(
    builder: &mut Builder<C>,
    challenger: &mut DuplexChallengerVariable<C>,
    nbits: usize,
    witness: Felt<C::F>,
) {
    let nbits = builder.eval_expr(Usize::from(nbits));
    challenger.observe(builder, witness);
    let bits = challenger.sample_bits(builder, nbits);
    builder.range(0, nbits).for_each(|index_vec, builder| {
        let bit = builder.get(&bits, index_vec[0]);
        builder.assert_eq::<Var<C::N>>(bit, Usize::from(0));
    });
}

pub fn clone_challenger_state<C: Config>(
    builder: &mut Builder<C>,
    src: &DuplexChallengerVariable<C>,
) -> DuplexChallengerVariable<C> {
    let dst = DuplexChallengerVariable::new(builder);
    builder
        .range(0, dst.sponge_state.len())
        .for_each(|idx_vec, builder| {
            let value = builder.get(&src.sponge_state, idx_vec[0]);
            builder.set(&dst.sponge_state, idx_vec[0], value);
        });

    let input_offset = src.input_ptr - src.io_empty_ptr;
    builder.assign(&dst.input_ptr, input_offset + dst.io_empty_ptr);

    let output_offset = src.output_ptr - src.io_empty_ptr;
    builder.assign(&dst.output_ptr, output_offset + dst.io_empty_ptr);
    dst
}

pub fn challenger_add_forked_index<C: Config>(
    builder: &mut Builder<C>,
    challenger: &mut DuplexChallengerVariable<C>,
    index: &Usize<C::N>,
) {
    let felt = builder.unsafe_cast_var_to_felt(index.get_var());
    challenger.observe(builder, felt);
}
