use ff_ext::{BabyBearExt4, ExtensionField as CenoExtensionField, SmallField};
use openvm_native_compiler::prelude::*;
use openvm_native_recursion::challenger::CanSampleBitsVariable;
use openvm_native_recursion::challenger::{duplex::DuplexChallengerVariable, CanObserveVariable};
use openvm_stark_backend::p3_field::FieldAlgebra;

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
