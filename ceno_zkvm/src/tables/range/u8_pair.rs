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
use ff_ext::ExtensionField;
use rayon::iter::{IndexedParallelIterator, IntoParallelIterator, ParallelIterator};

const NUM_U8_PAIRS: usize = 1 << 16;

#[derive(Clone, Debug)]
pub struct U8PairTableConfig {
    tbl_a: Fixed,
    tbl_b: Fixed,
    mlt: WitIn,
}

pub struct U8PairTableCircuit<E>(PhantomData<E>);

impl<E: ExtensionField> U8PairTableCircuit<E> {
    pub fn construct_circuit(cb: &mut CircuitBuilder<E>) -> Result<U8PairTableConfig, ZKVMError> {
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

    pub fn generate_fixed_traces(
        config: &U8PairTableConfig,
        fixed: &mut RowMajorMatrix<E::BaseField>,
    ) {
        assert!(fixed.num_instances() >= NUM_U8_PAIRS);

        fixed
            .par_iter_mut()
            .with_min_len(MIN_PAR_SIZE)
            .zip((0..NUM_U8_PAIRS).into_par_iter())
            .for_each(|(row, i)| {
                let a = i & 0xff;
                let b = (i >> 8) & 0xff;
                set_fixed_val!(row, config.tbl_a, E::BaseField::from(a as u64));
                set_fixed_val!(row, config.tbl_b, E::BaseField::from(b as u64));
            });
    }

    pub fn assign_instances(
        config: &U8PairTableConfig,
        multiplicity: &[HashMap<u64, usize>],
        witness: &mut RowMajorMatrix<E::BaseField>,
    ) {
        assert!(witness.num_instances() >= NUM_U8_PAIRS);

        let mut mlts = vec![0; NUM_U8_PAIRS];
        for (idx, mlt) in &multiplicity[ROMType::U8Pair as usize] {
            mlts[*idx as usize] = *mlt;
        }

        witness
            .par_iter_mut()
            .with_min_len(MIN_PAR_SIZE)
            .zip(mlts.into_par_iter())
            .for_each(|(row, mlt)| {
                set_val!(row, config.mlt, E::BaseField::from(mlt as u64));
            });
    }
}
