use itertools::Itertools;
use openvm_native_compiler::{
    asm::AsmConfig,
    ir::{Array, Builder, Config},
    prelude::*,
};
use openvm_native_recursion::hints::{Hintable, VecAutoHintable};
pub type F = BabyBear;
pub type E = BinomialExtensionField<F, 4>;
pub type InnerConfig = AsmConfig<F, E>;

use openvm_stark_backend::p3_field::extension::BinomialExtensionField;
use openvm_stark_sdk::p3_baby_bear::BabyBear;
use serde::Deserialize;

#[derive(DslVariable, Clone)]
pub struct PointVariable<C: Config> {
    pub fs: Array<C, Ext<C::F, C::EF>>,
}

#[derive(DslVariable, Clone)]
pub struct PointAndEvalVariable<C: Config> {
    pub point: PointVariable<C>,
    pub eval: Ext<C::F, C::EF>,
}

#[derive(DslVariable, Clone)]
pub struct IOPProverMessageVariable<C: Config> {
    pub evaluations: Array<C, Ext<C::F, C::EF>>,
}

#[derive(DslVariable, Clone)]
pub struct IOPProverMessageVecVariable<C: Config> {
    pub prover_message_size: Var<C::N>,
    pub length: Var<C::N>,
    pub evaluations: Array<C, Ext<C::F, C::EF>>,
}

impl<C: Config> IOPProverMessageVecVariable<C> {
    pub fn get(&self, builder: &mut Builder<C>, index: Var<C::N>) -> Array<C, Ext<C::F, C::EF>> {
        let start: Var<C::N> = builder.eval(self.prover_message_size * index);
        let end: Var<C::N> = builder.eval(start + self.prover_message_size);
        self.evaluations.slice(builder, start, end)
    }

    pub fn len(&self) -> Var<C::N> {
        self.length
    }
}

#[derive(DslVariable, Clone)]
pub struct ThreeDimensionalVecVariable<C: Config> {
    pub inner_inner_length: Var<C::N>,
    pub inner_length: Var<C::N>,
    pub length: Var<C::N>,
    pub data: Array<C, Ext<C::F, C::EF>>,
}

impl<C: Config> ThreeDimensionalVecVariable<C> {
    pub fn get(&self, builder: &mut Builder<C>, index: Var<C::N>) -> Array<C, Ext<C::F, C::EF>> {
        let start: Var<C::N> = builder.eval(self.inner_inner_length * self.inner_length * index);
        let end: Var<C::N> = builder.eval(start + self.inner_inner_length * self.inner_length);
        self.data.slice(builder, start, end)
    }

    pub fn get_inner(
        &self,
        builder: &mut Builder<C>,
        outer_index: Var<C::N>,
        inner_index: Var<C::N>,
    ) -> Array<C, Ext<C::F, C::EF>> {
        let start: Var<C::N> = builder.eval(
            self.inner_inner_length * self.inner_length * outer_index
                + self.inner_inner_length * inner_index,
        );
        let end: Var<C::N> = builder.eval(start + self.inner_inner_length);
        self.data.slice(builder, start, end)
    }

    pub fn len(&self) -> Var<C::N> {
        self.length
    }
}

#[derive(Clone, Deserialize)]
pub struct Point {
    pub fs: Vec<E>,
}
impl Hintable<InnerConfig> for Point {
    type HintVariable = PointVariable<InnerConfig>;

    fn read(builder: &mut Builder<InnerConfig>) -> Self::HintVariable {
        PointVariable {
            fs: builder.hint_exts(),
        }
    }

    fn write(&self) -> Vec<Vec<<InnerConfig as Config>::N>> {
        let mut stream = Vec::new();
        stream.extend(self.fs.write());
        stream
    }
}
impl VecAutoHintable for Point {}

pub struct PointAndEval {
    pub point: Point,
    pub eval: E,
}
impl Hintable<InnerConfig> for PointAndEval {
    type HintVariable = PointAndEvalVariable<InnerConfig>;

    fn read(builder: &mut Builder<InnerConfig>) -> Self::HintVariable {
        let point = Point::read(builder);
        let eval = E::read(builder);
        PointAndEvalVariable { point, eval }
    }

    fn write(&self) -> Vec<Vec<<InnerConfig as Config>::N>> {
        let mut stream = Vec::new();
        stream.extend(self.point.write());
        stream.extend(self.eval.write());
        stream
    }
}
impl VecAutoHintable for PointAndEval {}

#[derive(Debug, Default, Deserialize)]
pub struct ThreeDimensionalVector {
    pub inner_inner_length: usize,
    pub inner_length: usize,
    pub outer_length: usize,
    /// Flattened data
    pub data: Vec<E>,
}

impl ThreeDimensionalVector {
    pub fn get(&self, outer_index: usize) -> &[E] {
        let start = outer_index * self.inner_length * self.inner_inner_length;
        let end = start + self.inner_length * self.inner_inner_length;
        &self.data[start..end]
    }

    pub fn get_inner(&self, outer_index: usize, inner_index: usize) -> &[E] {
        let start = outer_index * self.inner_length * self.inner_inner_length
            + inner_index * self.inner_inner_length;
        let end = start + self.inner_inner_length;
        &self.data[start..end]
    }
}

impl From<Vec<Vec<Vec<E>>>> for ThreeDimensionalVector {
    fn from(data: Vec<Vec<Vec<E>>>) -> Self {
        let inner_inner_length = if data.len() == 0 {
            0
        } else {
            if data[0].len() == 0 {
                0
            } else {
                data[0][0].len()
            }
        };
        let inner_length = if data.len() == 0 { 0 } else { data[0].len() };
        let outer_length = data.len();
        let flattened_data = data.into_iter().flatten().flatten().collect();
        ThreeDimensionalVector {
            inner_inner_length,
            inner_length,
            outer_length,
            data: flattened_data,
        }
    }
}

impl Hintable<InnerConfig> for ThreeDimensionalVector {
    type HintVariable = ThreeDimensionalVecVariable<InnerConfig>;

    fn read(builder: &mut Builder<InnerConfig>) -> Self::HintVariable {
        let inner_inner_length: Var<F> = usize::read(builder);
        let inner_length: Var<F> = usize::read(builder);
        let length: Var<F> = usize::read(builder);
        let data = Vec::<E>::read(builder);
        builder.assert_eq::<Var<F>>(data.len(), inner_inner_length * inner_length * length);
        ThreeDimensionalVecVariable {
            inner_inner_length,
            inner_length,
            length,
            data,
        }
    }

    fn write(&self) -> Vec<Vec<<InnerConfig as Config>::N>> {
        let mut stream = Vec::new();
        stream.extend(<usize as Hintable<InnerConfig>>::write(
            &self.inner_inner_length,
        ));
        stream.extend(<usize as Hintable<InnerConfig>>::write(&self.inner_length));
        stream.extend(<usize as Hintable<InnerConfig>>::write(&self.outer_length));
        stream.extend(self.data.write());
        stream
    }
}
