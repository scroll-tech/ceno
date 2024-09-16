use std::{collections::HashMap, marker::PhantomData, mem::MaybeUninit};

use crate::{
    circuit_builder::CircuitBuilder,
    error::ZKVMError,
    expression::{Expression, Fixed, ToExpr, WitIn},
    scheme::constants::MIN_PAR_SIZE,
    set_fixed_val, set_val,
    structs::ROMType,
    tables::TableCircuit,
    uint::constants::RANGE_CHIP_BIT_WIDTH,
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
    type FixedInput = ();
    type WitnessInput = ();

    fn name() -> String {
        "RANGE".into()
    }

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
        _input: &(),
    ) -> RowMajorMatrix<E::BaseField> {
        let num_u16s = 1 << 16;
        let mut fixed = RowMajorMatrix::<E::BaseField>::new(num_u16s, num_fixed);
        fixed
            .par_iter_mut()
            .with_min_len(MIN_PAR_SIZE)
            .zip((0..num_u16s).into_par_iter())
            .for_each(|(row, i)| {
                set_fixed_val!(row, config.u16_tbl, E::BaseField::from(i as u64));
            });

        fixed
    }

    fn assign_instances(
        config: &Self::TableConfig,
        num_witin: usize,
        multiplicity: &[HashMap<u64, usize>],
        _input: &(),
    ) -> Result<RowMajorMatrix<E::BaseField>, ZKVMError> {
        let multiplicity = &multiplicity[ROMType::U16 as usize];
        let mut u16_mlt = vec![0; 1 << RANGE_CHIP_BIT_WIDTH];
        for (limb, mlt) in multiplicity {
            u16_mlt[*limb as usize] = *mlt;
        }

        let mut witness = RowMajorMatrix::<E::BaseField>::new(u16_mlt.len(), num_witin);
        witness
            .par_iter_mut()
            .with_min_len(MIN_PAR_SIZE)
            .zip(u16_mlt.into_par_iter())
            .for_each(|(row, mlt)| {
                set_val!(row, config.u16_mlt, E::BaseField::from(mlt as u64));
            });

        Ok(witness)
    }
}
