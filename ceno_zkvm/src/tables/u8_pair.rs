use std::{collections::HashMap, marker::PhantomData, mem::MaybeUninit};

use crate::{
    circuit_builder::CircuitBuilder,
    error::ZKVMError,
    expression::{Expression, Fixed, ToExpr, WitIn},
    scheme::constants::MIN_PAR_SIZE,
    set_fixed_val, set_val,
    structs::ROMType,
    tables::TableCircuit,
    witness::RowMajorMatrix,
};
use ff_ext::ExtensionField;
use rayon::iter::{IndexedParallelIterator, IntoParallelIterator, ParallelIterator};

#[derive(Clone, Debug)]
pub struct U8PairTableConfig {
    tbl_a: Fixed,
    tbl_b: Fixed,
    mlt: WitIn,
}

pub struct U8PairTableCircuit<E>(PhantomData<E>);

impl<E: ExtensionField> TableCircuit<E> for U8PairTableCircuit<E> {
    type TableConfig = U8PairTableConfig;
    type FixedInput = ();
    type WitnessInput = ();

    fn name() -> String {
        "U8_PAIR".into()
    }

    fn construct_circuit(cb: &mut CircuitBuilder<E>) -> Result<U8PairTableConfig, ZKVMError> {
        let tbl_a = cb.create_fixed(|| "tbl_a")?;
        let tbl_b = cb.create_fixed(|| "tbl_b")?;
        let mlt = cb.create_witin(|| "mlt")?;

        let rlc_record = cb.rlc_chip_record(vec![
            Expression::Constant(E::BaseField::from(ROMType::U8Pair as u64)),
            Expression::Fixed(tbl_a.clone()),
            Expression::Fixed(tbl_b.clone()),
        ]);

        cb.lk_table_record(|| "u8_pair_table", rlc_record, mlt.expr())?;

        Ok(U8PairTableConfig { tbl_a, tbl_b, mlt })
    }

    fn generate_fixed_traces(
        config: &U8PairTableConfig,
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
                let a = i & 0xff;
                let b = (i >> 8) & 0xff;
                set_fixed_val!(row, config.tbl_a, E::BaseField::from(a as u64));
                set_fixed_val!(row, config.tbl_b, E::BaseField::from(b as u64));
            });

        fixed
    }

    fn assign_instances(
        config: &Self::TableConfig,
        num_witin: usize,
        multiplicity: &[HashMap<u64, usize>],
        _input: &(),
    ) -> Result<RowMajorMatrix<E::BaseField>, ZKVMError> {
        let multiplicity = &multiplicity[ROMType::U8Pair as usize];
        let mut mlts = vec![0; 1 << 16];
        for (idx, mlt) in multiplicity {
            mlts[*idx as usize] = *mlt;
        }

        let mut witness = RowMajorMatrix::<E::BaseField>::new(mlts.len(), num_witin);
        witness
            .par_iter_mut()
            .with_min_len(MIN_PAR_SIZE)
            .zip(mlts.into_par_iter())
            .for_each(|(row, mlt)| {
                set_val!(row, config.mlt, E::BaseField::from(mlt as u64));
            });

        Ok(witness)
    }
}
