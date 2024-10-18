use std::{marker::PhantomData, mem::MaybeUninit};

use ff_ext::ExtensionField;
use goldilocks::SmallField;
use itertools::Itertools;
use rayon::iter::{IndexedParallelIterator, IntoParallelIterator, ParallelIterator};

use crate::{
    circuit_builder::CircuitBuilder,
    error::ZKVMError,
    expression::{Expression, Fixed, ToExpr, WitIn},
    scheme::constants::MIN_PAR_SIZE,
    set_fixed_val, set_val,
    witness::RowMajorMatrix,
};

use super::ram_circuit::RamTable;

#[derive(Clone, Debug)]
pub struct RamTableConfig<RAM: RamTable + Send + Sync + Clone> {
    init_v: Vec<Fixed>,
    addr: Fixed,

    final_v: Vec<WitIn>,
    phantom: PhantomData<RAM>,
}

impl<RAM: RamTable + Send + Sync + Clone> RamTableConfig<RAM> {
    pub fn construct_circuit<E: ExtensionField>(
        cb: &mut CircuitBuilder<E>,
    ) -> Result<Self, ZKVMError> {
        let init_v = (0..RAM::V_LIMBS)
            .map(|i| cb.create_fixed(|| format!("init_v_limb_{i}")))
            .collect::<Result<Vec<Fixed>, ZKVMError>>()?;
        let addr = cb.create_fixed(|| "addr")?;

        let final_v = (0..RAM::V_LIMBS)
            .map(|i| cb.create_witin(|| format!("final_v_limb_{i}")))
            .collect::<Result<Vec<WitIn>, ZKVMError>>()?;

        let init_table = cb.rlc_chip_record(
            [
                vec![(RAM::RAM_TYPE as usize).into()],
                vec![Expression::Fixed(addr)],
                init_v.iter().map(|v| v.expr()).collect_vec(),
            ]
            .concat(),
        );

        let final_table = cb.rlc_chip_record(
            [
                // a v t
                vec![(RAM::RAM_TYPE as usize).into()],
                vec![Expression::Fixed(addr)],
                final_v.iter().map(|v| v.expr()).collect_vec(),
            ]
            .concat(),
        );

        cb.w_table_record(|| "init_table", RAM::len(), init_table)?;
        cb.r_table_record(|| "final_table", RAM::len(), final_table)?;

        Ok(Self {
            init_v,
            addr,
            final_v,
            phantom: PhantomData,
        })
    }

    /// TODO consider taking RowMajorMatrix from externally, since both pattern are 1D vector
    /// with that, we can save one allocation cost
    pub fn gen_init_state<F: SmallField>(
        &self,
        num_fixed: usize,
        init_v: &[u32], // value limb are concated into 1d slice
    ) -> RowMajorMatrix<F> {
        assert_eq!(num_fixed, RAM::V_LIMBS + 1); // +1 for addr
        assert_eq!(init_v.len() % RAM::V_LIMBS, 0);
        assert_eq!(init_v.len() / RAM::V_LIMBS, RAM::len());
        // for ram in memory offline check
        let mut init_table = RowMajorMatrix::<F>::new(RAM::len(), num_fixed);

        init_table
            .par_iter_mut()
            .with_min_len(MIN_PAR_SIZE)
            .zip(init_v.into_par_iter().chunks(RAM::V_LIMBS))
            .enumerate()
            .for_each(|(i, (row, v))| {
                self.init_v.iter().zip(v).for_each(|(c, v)| {
                    set_fixed_val!(row, c, (*v as u64).into());
                });
                set_fixed_val!(row, self.addr, (RAM::addr(i) as u64).into());
            });

        init_table
    }

    /// TODO consider taking RowMajorMatrix from externally, since both pattern are 1D vector
    /// with that, we can save one allocation cost
    pub fn assign_instances<F: SmallField>(
        &self,
        num_witness: usize,
        final_v: &[u32], // value limb are concated into 1d slice
    ) -> Result<RowMajorMatrix<F>, ZKVMError> {
        assert_eq!(num_witness, RAM::V_LIMBS);
        assert_eq!(final_v.len() % RAM::V_LIMBS, 0);
        assert_eq!(final_v.len() / RAM::V_LIMBS, RAM::len());
        let mut final_table = RowMajorMatrix::<F>::new(RAM::len(), RAM::V_LIMBS);

        final_table
            .par_iter_mut()
            .with_min_len(MIN_PAR_SIZE)
            .zip(final_v.into_par_iter().chunks(RAM::V_LIMBS))
            .for_each(|(row, v)| {
                self.final_v.iter().zip(v).for_each(|(c, v)| {
                    set_val!(row, c, *v as u64);
                });
            });

        Ok(final_table)
    }
}
