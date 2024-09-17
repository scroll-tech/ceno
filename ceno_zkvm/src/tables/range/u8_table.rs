use ff_ext::ExtensionField;
use goldilocks::SmallField;
use rayon::iter::{IndexedParallelIterator, IntoParallelIterator, ParallelIterator};
use std::{collections::HashMap, mem::MaybeUninit};

use crate::{
    circuit_builder::CircuitBuilder,
    error::ZKVMError,
    expression::{Expression, Fixed, ToExpr, WitIn},
    scheme::constants::MIN_PAR_SIZE,
    set_fixed_val, set_val,
    structs::ROMType,
    witness::RowMajorMatrix,
};

pub type U8TableConfig = ScalarTableConfig;

#[derive(Clone, Debug)]
pub struct ScalarTableConfig {
    rom_type: ROMType,
    fixed: Fixed,
    mlt: WitIn,
}

impl ScalarTableConfig {
    pub fn construct_circuit<E: ExtensionField>(
        cb: &mut CircuitBuilder<E>,
        rom_type: ROMType,
    ) -> Result<Self, ZKVMError> {
        let fixed = cb.create_fixed(|| "fixed")?;
        let mlt = cb.create_witin(|| "mlt")?;

        let rlc_record = cb.rlc_chip_record(vec![
            Expression::Constant(E::BaseField::from(rom_type as u64)),
            Expression::Fixed(fixed.clone()),
        ]);

        cb.lk_table_record(|| "record", rlc_record, mlt.expr())?;

        Ok(Self {
            fixed,
            mlt,
            rom_type,
        })
    }

    pub fn generate_fixed_traces<F: SmallField>(&self, fixed: &mut RowMajorMatrix<F>) {
        let count = self.rom_type.count();
        assert!(fixed.num_instances() >= count);

        fixed
            .par_iter_mut()
            .with_min_len(MIN_PAR_SIZE)
            .zip(self.rom_type.gen().into_par_iter())
            .for_each(|(row, i)| {
                set_fixed_val!(row, self.fixed, F::from(i));
            });

        // Fill the rest with zeros, if any.
        fixed.par_iter_mut().skip(count).for_each(|row| {
            set_fixed_val!(row, self.fixed, F::ZERO);
        });
    }

    pub fn assign_instances<F: SmallField>(
        &self,
        multiplicity: &[HashMap<u64, usize>],
        witness: &mut RowMajorMatrix<F>,
    ) {
        let count = self.rom_type.count();
        assert!(witness.num_instances() >= count);

        let mut mlts = vec![0; count];
        for (idx, mlt) in &multiplicity[ROMType::U8 as usize] {
            mlts[*idx as usize] = *mlt;
        }

        witness
            .par_iter_mut()
            .with_min_len(MIN_PAR_SIZE)
            .zip(mlts.into_par_iter())
            .for_each(|(row, mlt)| {
                set_val!(row, self.mlt, F::from(mlt as u64));
            });

        // Fill the rest with zeros, if any.
        witness.par_iter_mut().skip(count).for_each(|row| {
            set_val!(row, self.mlt, F::ZERO);
        });
    }
}
