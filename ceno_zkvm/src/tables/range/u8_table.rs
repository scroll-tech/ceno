use ff::Field;
use ff_ext::ExtensionField;
use rayon::iter::{IndexedParallelIterator, IntoParallelIterator, ParallelIterator};
use std::{collections::HashMap, marker::PhantomData, mem::MaybeUninit};

use crate::{
    circuit_builder::CircuitBuilder,
    error::ZKVMError,
    expression::{Expression, Fixed, ToExpr, WitIn},
    scheme::constants::MIN_PAR_SIZE,
    set_fixed_val, set_val,
    structs::ROMType,
    witness::RowMajorMatrix,
};

const NUM_U8: usize = 1 << 8;

#[derive(Clone, Debug)]
pub struct U8TableConfig {
    u8_fixed: Fixed,
    mlt: WitIn,
}

pub struct U8TableCircuit<E>(PhantomData<E>);

impl<E: ExtensionField> U8TableCircuit<E> {
    pub fn construct_circuit(cb: &mut CircuitBuilder<E>) -> Result<U8TableConfig, ZKVMError> {
        let u8_fixed = cb.create_fixed(|| "u8_fixed")?;
        let mlt = cb.create_witin(|| "mlt")?;

        let rlc_record = cb.rlc_chip_record(vec![
            Expression::Constant(E::BaseField::from(ROMType::U8 as u64)),
            Expression::Fixed(u8_fixed.clone()),
        ]);

        cb.lk_table_record(|| "u8_record", rlc_record, mlt.expr())?;

        Ok(U8TableConfig { u8_fixed, mlt })
    }

    pub fn generate_fixed_traces(config: &U8TableConfig, fixed: &mut RowMajorMatrix<E::BaseField>) {
        assert!(fixed.num_instances() >= NUM_U8);

        fixed
            .par_iter_mut()
            .with_min_len(MIN_PAR_SIZE)
            .zip((0..NUM_U8).into_par_iter())
            .for_each(|(row, i)| {
                set_fixed_val!(row, config.u8_fixed, E::BaseField::from(i as u64));
            });

        // Fill the rest with zeros, if any.
        fixed.par_iter_mut().skip(NUM_U8).for_each(|row| {
            set_fixed_val!(row, config.u8_fixed, E::BaseField::ZERO);
        });
    }

    pub fn assign_instances(
        config: &U8TableConfig,
        multiplicity: &[HashMap<u64, usize>],
        witness: &mut RowMajorMatrix<E::BaseField>,
    ) {
        assert!(witness.num_instances() >= NUM_U8);

        let mut mlts = vec![0; NUM_U8];
        for (idx, mlt) in &multiplicity[ROMType::U8 as usize] {
            mlts[*idx as usize] = *mlt;
        }

        witness
            .par_iter_mut()
            .with_min_len(MIN_PAR_SIZE)
            .zip(mlts.into_par_iter())
            .for_each(|(row, mlt)| {
                set_val!(row, config.mlt, E::BaseField::from(mlt as u64));
            });

        // Fill the rest with zeros, if any.
        witness.par_iter_mut().skip(NUM_U8).for_each(|row| {
            set_val!(row, config.mlt, E::BaseField::ZERO);
        });
    }
}
