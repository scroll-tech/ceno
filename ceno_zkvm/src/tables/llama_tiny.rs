//! Full fixed-domain nonlinear ROMs for the complete llama-tiny layer.

use std::marker::PhantomData;

use ff_ext::{ExtensionField, FieldInto, SmallField};
use gkr_iop::{error::CircuitBuilderError, tables::LookupTable};
use multilinear_extensions::{Expression, Fixed, ToExpr, WitIn};
use rayon::iter::{IndexedParallelIterator, ParallelIterator};
use rustc_hash::FxHashMap;
use witness::{InstancePaddingStrategy, RowMajorMatrix, set_fixed_val, set_val};

use crate::{
    circuit_builder::{CircuitBuilder, SetTableSpec},
    error::ZKVMError,
    structs::ProgramParams,
    tables::{RMMCollections, TableCircuit},
};

pub const LLAMA_TINY_ROM_ROWS: usize = 1 << 16;
const Q16_SCALE_F64: f64 = 65_536.0;
const RMS_EPSILON: f64 = 1.0e-6;

pub trait LlamaTinyRom: Send + Sync {
    const CATEGORY: LookupTable;
    const NAME: &'static str;
    const ROWS: usize = LLAMA_TINY_ROM_ROWS;

    fn input(index: usize) -> i64;
    fn output(index: usize) -> i64;
}

pub struct SoftmaxExp3Rom;
impl LlamaTinyRom for SoftmaxExp3Rom {
    const CATEGORY: LookupTable = LookupTable::LlamaSoftmaxExp3;
    const NAME: &'static str = "LLAMA_TINY_SOFTMAX_EXP3";

    fn input(index: usize) -> i64 {
        index as i64
    }

    fn output(index: usize) -> i64 {
        (1024.0 * (-(index as f64) / (Q16_SCALE_F64 * 2.0f64.sqrt())).exp() + 0.5) as i64
    }
}

pub struct SoftmaxExp4Rom;
impl LlamaTinyRom for SoftmaxExp4Rom {
    const CATEGORY: LookupTable = LookupTable::LlamaSoftmaxExp4;
    const NAME: &'static str = "LLAMA_TINY_SOFTMAX_EXP4";

    fn input(index: usize) -> i64 {
        index as i64
    }

    fn output(index: usize) -> i64 {
        (1024.0 * (-(index as f64) / 2.0f64.sqrt()).exp() + 0.5) as i64
    }
}

pub struct RmsInvRom;
impl LlamaTinyRom for RmsInvRom {
    const CATEGORY: LookupTable = LookupTable::LlamaRmsInv;
    const NAME: &'static str = "LLAMA_TINY_RMS_INV";
    const ROWS: usize = 1 << 18;

    fn input(index: usize) -> i64 {
        index as i64
    }

    fn output(index: usize) -> i64 {
        // The key is sum(x_i^2) for H=2. Inputs are Q16, so this is
        // round(2^16 / sqrt(mean((x/2^16)^2) + 1e-6)).
        let denominator = (index as f64 / 2.0 + RMS_EPSILON * Q16_SCALE_F64.powi(2)).sqrt();
        (Q16_SCALE_F64.powi(2) / denominator + 0.5) as i64
    }
}

pub struct SwiGluRom;
impl LlamaTinyRom for SwiGluRom {
    const CATEGORY: LookupTable = LookupTable::LlamaSwiGlu;
    const NAME: &'static str = "LLAMA_TINY_SWIGLU";

    fn input(index: usize) -> i64 {
        i64::from(index as u16 as i16)
    }

    fn output(index: usize) -> i64 {
        let input = f64::from(index as u16 as i16);
        // Q12 input to Q16 x*sigmoid(x): the scale ratio is 2^4.
        (input * 16.0 / (1.0 + (-input / 4096.0).exp())).round() as i64
    }
}

#[derive(Clone, Debug)]
pub struct LlamaTinyRomConfig {
    input: Fixed,
    output: Fixed,
    multiplicity: WitIn,
}

impl LlamaTinyRomConfig {
    fn construct<E: ExtensionField>(
        cb: &mut CircuitBuilder<E>,
        category: LookupTable,
        rows: usize,
    ) -> Result<Self, CircuitBuilderError> {
        let input = cb.create_fixed(|| "input");
        let output = cb.create_fixed(|| "output");
        let multiplicity = cb.create_witin(|| "multiplicity");
        cb.lk_table_record(
            || "llama_tiny_rom_record",
            SetTableSpec {
                len: Some(rows),
                structural_witins: vec![],
            },
            category,
            vec![Expression::Fixed(input), Expression::Fixed(output)],
            multiplicity.expr(),
        )?;
        Ok(Self {
            input,
            output,
            multiplicity,
        })
    }

    fn fixed_trace<F: SmallField, R: LlamaTinyRom>(&self, num_fixed: usize) -> RowMajorMatrix<F> {
        let mut fixed = RowMajorMatrix::new(R::ROWS, num_fixed, InstancePaddingStrategy::Default);
        fixed.par_rows_mut().enumerate().for_each(|(index, row)| {
            set_fixed_val!(row, self.input, F::from_i64(R::input(index)));
            set_fixed_val!(row, self.output, F::from_i64(R::output(index)));
        });
        fixed
    }

    fn assign<F: SmallField>(
        &self,
        num_witin: usize,
        num_structural_witin: usize,
        multiplicity: &FxHashMap<u64, usize>,
        rows: usize,
    ) -> RMMCollections<F> {
        assert_eq!(num_structural_witin, 1);
        let mut witness = RowMajorMatrix::new(rows, num_witin, InstancePaddingStrategy::Default);
        let mut structural = RowMajorMatrix::new(
            rows,
            num_structural_witin.max(1),
            InstancePaddingStrategy::Default,
        );
        witness
            .par_rows_mut()
            .zip_eq(structural.par_rows_mut())
            .enumerate()
            .for_each(|(index, (row, structural_row))| {
                set_val!(
                    row,
                    self.multiplicity,
                    multiplicity
                        .get(&(index as u64))
                        .copied()
                        .unwrap_or_default() as u64
                );
                *structural_row.last_mut().unwrap() = F::ONE;
            });
        [witness, structural]
    }
}

pub struct LlamaTinyRomCircuit<E, R>(PhantomData<(E, R)>);

impl<E: ExtensionField, R: LlamaTinyRom> TableCircuit<E> for LlamaTinyRomCircuit<E, R> {
    type TableConfig = LlamaTinyRomConfig;
    type FixedInput = ();
    type WitnessInput<'a> = ();

    fn name() -> String {
        R::NAME.into()
    }

    fn construct_circuit(
        cb: &mut CircuitBuilder<E>,
        _: &ProgramParams,
    ) -> Result<Self::TableConfig, ZKVMError> {
        Ok(cb.namespace(
            || R::NAME,
            |cb| LlamaTinyRomConfig::construct(cb, R::CATEGORY, R::ROWS),
        )?)
    }

    fn generate_fixed_traces(
        config: &Self::TableConfig,
        num_fixed: usize,
        _: &(),
    ) -> RowMajorMatrix<E::BaseField> {
        config.fixed_trace::<E::BaseField, R>(num_fixed)
    }

    fn assign_instances(
        config: &Self::TableConfig,
        num_witin: usize,
        num_structural_witin: usize,
        multiplicities: &[FxHashMap<u64, usize>],
        _: &(),
    ) -> Result<RMMCollections<E::BaseField>, ZKVMError> {
        Ok(config.assign(
            num_witin,
            num_structural_witin,
            &multiplicities[R::CATEGORY as usize],
            R::ROWS,
        ))
    }
}

pub type SoftmaxExp3TableCircuit<E> = LlamaTinyRomCircuit<E, SoftmaxExp3Rom>;
pub type SoftmaxExp4TableCircuit<E> = LlamaTinyRomCircuit<E, SoftmaxExp4Rom>;
pub type RmsInvTableCircuit<E> = LlamaTinyRomCircuit<E, RmsInvRom>;
pub type SwiGluTableCircuit<E> = LlamaTinyRomCircuit<E, SwiGluRom>;
