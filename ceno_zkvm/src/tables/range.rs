use std::{marker::PhantomData, mem::MaybeUninit};

use crate::{
    circuit_builder::CircuitBuilder,
    error::ZKVMError,
    expression::{Expression, Fixed, ToExpr, WitIn},
    set_fixed_val, set_val,
    structs::ROMType,
    tables::TableCircuit,
    witness::RowMajorMatrix,
};
use ff_ext::ExtensionField;
use rayon::iter::{IndexedParallelIterator, IntoParallelIterator, ParallelIterator};

#[derive(Clone, Debug)]
pub struct RangeTableConfig {
    u16_tbl: Fixed,
    u16_mlt: WitIn,
}

pub struct RangeTableCircuit<E>(PhantomData<E>);

impl<E: ExtensionField> TableCircuit<E> for RangeTableCircuit<E> {
    type TableConfig = RangeTableConfig;
    type Input = usize;

    fn name() -> String {
        "RANGE".into()
    }

    #[allow(unused)]
    fn construct_circuit(cb: &mut CircuitBuilder<E>) -> Result<RangeTableConfig, ZKVMError> {
        let u16_tbl = cb.create_fixed(|| "u16_tbl")?;
        let u16_mlt = cb.create_witin(|| "u16_mlt")?;

        let u16_table_values = cb.rlc_chip_record(vec![
            Expression::Constant(E::BaseField::from(ROMType::U16 as u64)),
            Expression::Fixed(u16_tbl.clone()),
        ]);

        cb.lk_table_record(|| "u16 table", u16_table_values, u16_mlt.expr())?;

        Ok(RangeTableConfig { u16_tbl, u16_mlt })
    }

    fn generate_fixed_traces(
        config: &RangeTableConfig,
        num_fixed: usize,
    ) -> RowMajorMatrix<E::BaseField> {
        let num_u16s = 1 << 16;
        let mut fixed = RowMajorMatrix::<E::BaseField>::new(num_u16s, num_fixed);
        fixed
            .par_iter_mut()
            .zip((0..num_u16s).into_par_iter())
            .for_each(|(row, i)| {
                set_fixed_val!(row, config.u16_tbl.0, E::BaseField::from(i as u64));
            });

        fixed
    }
    #[allow(unused)]
    fn assign_instances(
        config: &Self::TableConfig,
        num_witin: usize,
        inputs: &[Self::Input],
    ) -> Result<RowMajorMatrix<E::BaseField>, ZKVMError> {
        let num_u16s = 1 << 16;
        let mut u16_mlt = vec![0; num_u16s];
        for limb in inputs {
            u16_mlt[*limb] += 1;
        }
        tracing::debug!("u16_mult[4] = {}", u16_mlt[4]);

        let mut witness = RowMajorMatrix::<E::BaseField>::new(u16_mlt.len(), num_witin);
        witness
            .par_iter_mut()
            .zip(u16_mlt.into_par_iter())
            .for_each(|(row, mlt)| {
                set_val!(row, config.u16_mlt, E::BaseField::from(mlt));
            });

        Ok(witness)
    }
}
