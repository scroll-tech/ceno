use openvm_native_compiler::{asm::AsmConfig, prelude::*};
use openvm_native_recursion::hints::{Hintable, VecAutoHintable};
use openvm_stark_sdk::p3_baby_bear::BabyBear;
use p3::field::extension::BinomialExtensionField;
use serde::Deserialize;

use super::structs::DEGREE;

pub const DIGEST_ELEMS: usize = 8;

pub type F = BabyBear;
pub type E = BinomialExtensionField<F, DEGREE>;
pub type InnerConfig = AsmConfig<F, E>;

#[derive(Deserialize, Default, Debug)]
pub struct Hash {
    pub value: [F; DIGEST_ELEMS],
}

impl From<p3::symmetric::Hash<F, F, DIGEST_ELEMS>> for Hash {
    fn from(hash: p3::symmetric::Hash<F, F, DIGEST_ELEMS>) -> Self {
        Hash { value: hash.into() }
    }
}

#[derive(DslVariable, Clone)]
pub struct HashVariable<C: Config> {
    pub value: Array<C, Felt<C::F>>,
}

impl VecAutoHintable for Hash {}

impl Hintable<InnerConfig> for Hash {
    type HintVariable = HashVariable<InnerConfig>;

    fn read(builder: &mut Builder<InnerConfig>) -> Self::HintVariable {
        let value = builder.hint_felts_fixed(DIGEST_ELEMS);

        HashVariable { value }
    }

    fn write(&self) -> Vec<Vec<<InnerConfig as Config>::N>> {
        self.value.map(|felt| vec![felt]).to_vec()
    }
}

#[cfg(test)]
mod tests {
    use openvm_circuit::arch::{SystemConfig, VmExecutor};
    use openvm_native_circuit::{Native, NativeConfig};
    use openvm_native_compiler::asm::AsmBuilder;

    use crate::basefold_verifier::basefold::HashDigest;

    use super::*;
    #[test]
    fn test_read_to_hash_variable() {
        // simple test program
        let mut builder = AsmBuilder::<F, E>::default();
        let _digest = HashDigest::read(&mut builder);
        builder.halt();

        // configure the VM executor
        let system_config = SystemConfig::default().with_max_segment_len(1 << 20);
        let config = NativeConfig::new(system_config, Native);
        let executor = VmExecutor::new(config);

        // prepare input
        let mut input = Vec::new();
        input.extend(Hash::default().write());

        // execute the program
        let program = builder.compile_isa();
        executor.execute(program, input).unwrap();
    }
}
