use openvm_native_compiler::{asm::AsmConfig, ir::*};
use openvm_native_compiler_derive::DslVariable;
use openvm_native_recursion::hints::{Hintable, VecAutoHintable};
use openvm_stark_sdk::p3_baby_bear::BabyBear;
use p3::field::extension::BinomialExtensionField;

pub const DEGREE: usize = 4;

pub type F = BabyBear;
pub type E = BinomialExtensionField<F, DEGREE>;
pub type InnerConfig = AsmConfig<F, E>;

#[derive(DslVariable, Clone)]
pub struct DimensionsVariable<C: Config> {
    pub width: Var<C::N>,
    pub height: Var<C::N>,
}

pub struct Dimensions {
    pub width: usize,
    pub height: usize,
}

impl VecAutoHintable for Dimensions {}

impl Hintable<InnerConfig> for Dimensions {
    type HintVariable = DimensionsVariable<InnerConfig>;

    fn read(builder: &mut Builder<InnerConfig>) -> Self::HintVariable {
        let width = usize::read(builder);
        let height = usize::read(builder);

        DimensionsVariable { width, height }
    }

    fn write(&self) -> Vec<Vec<<InnerConfig as Config>::N>> {
        let mut stream = Vec::new();
        stream.extend(<usize as Hintable<InnerConfig>>::write(&self.width));
        stream.extend(<usize as Hintable<InnerConfig>>::write(&self.height));
        stream
    }
}
