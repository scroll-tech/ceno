use openvm_native_compiler::{asm::AsmConfig, prelude::*};
use openvm_native_recursion::{hints::Hintable, vars::HintSlice};
use openvm_stark_sdk::p3_baby_bear::BabyBear;
use p3::field::extension::BinomialExtensionField;

use super::{mmcs::*, structs::*};

pub type F = BabyBear;
pub type E = BinomialExtensionField<F, DEGREE>;
pub type InnerConfig = AsmConfig<F, E>;

pub struct ExtMmcsVerifierInput {
    pub commit: MmcsCommitment,
    pub dimensions: Vec<usize>,
    pub index: usize,
    pub opened_values: Vec<Vec<E>>,
    pub proof: MmcsProof,
}

#[derive(DslVariable, Clone)]
pub struct ExtMmcsVerifierInputVariable<C: Config> {
    pub commit: MmcsCommitmentVariable<C>,
    pub dimensions: Array<C, Var<C::N>>,
    pub index_bits: Array<C, Var<C::N>>,
    pub opened_values: Array<C, Array<C, Ext<C::F, C::EF>>>,
    pub proof: HintSlice<C>,
}

impl Hintable<InnerConfig> for ExtMmcsVerifierInput {
    type HintVariable = ExtMmcsVerifierInputVariable<InnerConfig>;

    fn read(builder: &mut Builder<InnerConfig>) -> Self::HintVariable {
        let commit = MmcsCommitment::read(builder);
        let dimensions = Vec::<usize>::read(builder);
        let index_bits = Vec::<usize>::read(builder);
        let opened_values = Vec::<Vec<E>>::read(builder);
        let length = Usize::from(builder.hint_var());
        let id = Usize::from(builder.hint_load());
        let proof = HintSlice { length, id };

        ExtMmcsVerifierInputVariable {
            commit,
            dimensions,
            index_bits,
            opened_values,
            proof,
        }
    }

    fn write(&self) -> Vec<Vec<<InnerConfig as Config>::N>> {
        let mut stream = Vec::new();
        stream.extend(self.commit.write());
        stream.extend(self.dimensions.write());
        let mut index_bits = Vec::new();
        let mut index = self.index;
        while index > 0 {
            index_bits.push(index % 2);
            index /= 2;
        }
        stream.extend(<Vec<usize> as Hintable<InnerConfig>>::write(&index_bits));
        stream.extend(self.opened_values.write());
        stream.extend(
            self.proof
                .iter()
                .map(|p| p.to_vec())
                .collect::<Vec<_>>()
                .write(),
        );
        stream
    }
}

pub(crate) fn ext_mmcs_verify_batch<C: Config>(
    builder: &mut Builder<C>,
    input: ExtMmcsVerifierInputVariable<C>,
) {
    let dimensions = match input.dimensions {
        Array::Dyn(ptr, len) => Array::Dyn(ptr, len.clone()),
        _ => panic!("Expected a dynamic array of felts"),
    };

    builder.verify_batch_ext(
        &dimensions,
        &input.opened_values,
        input.proof.id.get_var(),
        &input.index_bits,
        &input.commit.value,
    );
}
