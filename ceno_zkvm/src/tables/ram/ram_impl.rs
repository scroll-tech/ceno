use std::{marker::PhantomData, mem::MaybeUninit};

use ff_ext::ExtensionField;
use goldilocks::SmallField;
use itertools::Itertools;
use rayon::iter::{IndexedParallelIterator, IntoParallelIterator, ParallelIterator};

use crate::{
    circuit_builder::CircuitBuilder,
    error::ZKVMError,
    expression::{Expression, Fixed, ToExpr, WitIn},
    instructions::riscv::constants::{LIMB_BITS, LIMB_MASK},
    scheme::constants::MIN_PAR_SIZE,
    set_fixed_val, set_val,
    witness::RowMajorMatrix,
};

use super::{
    MemInitRecord,
    ram_circuit::{MemFinalRecord, RamTable},
};

#[derive(Clone, Debug)]
pub struct RamTableConfig<RAM: RamTable + Send + Sync + Clone> {
    init_v: Vec<Fixed>,
    addr: Fixed,

    final_v: Vec<WitIn>,
    final_cycle: WitIn,

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
        let final_cycle = cb.create_witin(|| "final_cycle")?;

        let init_table = cb.rlc_chip_record(
            [
                vec![(RAM::RAM_TYPE as usize).into()],
                vec![Expression::Fixed(addr)],
                init_v.iter().map(|v| v.expr()).collect_vec(),
                vec![Expression::ZERO], // Initial cycle.
            ]
            .concat(),
        );

        let final_table = cb.rlc_chip_record(
            [
                // a v t
                vec![(RAM::RAM_TYPE as usize).into()],
                vec![Expression::Fixed(addr)],
                final_v.iter().map(|v| v.expr()).collect_vec(),
                vec![final_cycle.expr()],
            ]
            .concat(),
        );

        cb.w_table_record(|| "init_table", RAM::len(), init_table)?;
        cb.r_table_record(|| "final_table", RAM::len(), final_table)?;

        Ok(Self {
            init_v,
            addr,
            final_v,
            final_cycle,
            phantom: PhantomData,
        })
    }

    pub fn gen_init_state<F: SmallField>(
        &self,
        num_fixed: usize,
        init_v: &[MemInitRecord],
    ) -> RowMajorMatrix<F> {
        assert_eq!(init_v.len(), RAM::len());
        // for ram in memory offline check
        let mut init_table = RowMajorMatrix::<F>::new(RAM::len(), num_fixed);

        init_table
            .par_iter_mut()
            .with_min_len(MIN_PAR_SIZE)
            .zip(init_v.into_par_iter())
            .for_each(|(row, rec)| {
                if self.init_v.len() == 1 {
                    // Assign value directly.
                    set_fixed_val!(row, self.init_v[0], (rec.value as u64).into());
                } else {
                    // Assign value limbs.
                    self.init_v.iter().enumerate().for_each(|(l, limb)| {
                        let val = (rec.value >> (l * LIMB_BITS)) & LIMB_MASK;
                        set_fixed_val!(row, limb, (val as u64).into());
                    });
                }
                set_fixed_val!(row, self.addr, (rec.addr as u64).into());
            });

        init_table
    }

    /// TODO consider taking RowMajorMatrix as argument to save allocations.
    pub fn assign_instances<F: SmallField>(
        &self,
        num_witness: usize,
        final_v: &[MemFinalRecord],
    ) -> Result<RowMajorMatrix<F>, ZKVMError> {
        assert_eq!(final_v.len(), RAM::len());
        let mut final_table = RowMajorMatrix::<F>::new(RAM::len(), num_witness);

        final_table
            .par_iter_mut()
            .with_min_len(MIN_PAR_SIZE)
            .zip(final_v.into_par_iter())
            .for_each(|(row, rec)| {
                if self.final_v.len() == 1 {
                    // Assign value directly.
                    set_fixed_val!(row, self.init_v[0], (rec.value as u64).into());
                } else {
                    // Assign value limbs.
                    self.final_v.iter().enumerate().for_each(|(l, limb)| {
                        let val = (rec.value >> (l * LIMB_BITS)) & LIMB_MASK;
                        set_val!(row, limb, val as u64);
                    });
                }
                set_val!(row, self.final_cycle, rec.cycle);
            });

        Ok(final_table)
    }
}
