use std::mem::MaybeUninit;

use ff_ext::ExtensionField;
use goldilocks::SmallField;
use rayon::iter::{IndexedParallelIterator, IntoParallelIterator, ParallelIterator};

use crate::{
    circuit_builder::CircuitBuilder,
    error::ZKVMError,
    expression::{Expression, Fixed, ToExpr, WitIn},
    scheme::constants::MIN_PAR_SIZE,
    set_fixed_val, set_val,
    structs::RAMType,
    witness::RowMajorMatrix,
};

#[derive(Clone, Debug)]
pub struct RamTableConfig {
    init_v: Fixed,
    init_t: Fixed,
    addr: Fixed,

    final_v: WitIn,
    final_t: WitIn,
}

impl RamTableConfig {
    pub fn construct_circuit<E: ExtensionField>(
        cb: &mut CircuitBuilder<E>,
        ram_type: RAMType,
        table_len: usize,
    ) -> Result<Self, ZKVMError> {
        let init_v = cb.create_fixed(|| "init_v")?;
        let addr = cb.create_fixed(|| "addr")?;
        let init_t = cb.create_fixed(|| "init_t")?; // this is zero vector

        let final_v = cb.create_witin(|| "final_v")?;
        let final_t = cb.create_witin(|| "final_t")?;

        let init_table = cb.rlc_chip_record(vec![
            (ram_type as usize).into(),
            Expression::Fixed(addr),
            Expression::Fixed(init_v),
            Expression::Fixed(init_t),
        ]);

        let final_table = cb.rlc_chip_record(vec![
            // a v t
            (ram_type as usize).into(),
            Expression::Fixed(addr),
            final_v.expr(),
            final_t.expr(),
        ]);

        cb.w_table_record(|| "init_table", table_len, init_table)?;
        cb.r_table_record(|| "final_table", table_len, final_table)?;

        Ok(Self {
            init_v,
            init_t,
            addr,
            final_v,
            final_t,
        })
    }

    pub fn gen_init_state<F: SmallField>(
        &self,
        num_fixed: usize,
        init_v: &[u32],
    ) -> RowMajorMatrix<F> {
        // for ram in memory offline check
        let mut init_table = RowMajorMatrix::<F>::new(init_v.len(), num_fixed);

        init_table
            .par_iter_mut()
            .with_min_len(MIN_PAR_SIZE)
            .zip((0..init_v.len()).into_par_iter())
            .for_each(|(row, i)| {
                set_fixed_val!(row, self.init_v, (init_v[i] as u64).into());
                set_fixed_val!(row, self.addr, (i as u64).into());
                set_fixed_val!(row, self.init_t, F::ZERO);
            });

        init_table
    }

    pub fn assign_instances<F: SmallField>(
        &self,
        num_witness: usize,
        final_v: &[u32],
        final_t: &[u32],
    ) -> Result<RowMajorMatrix<F>, ZKVMError> {
        assert_eq!(final_v.len(), final_t.len());
        let length = final_v.len();
        let mut final_table = RowMajorMatrix::<F>::new(length, num_witness);

        final_table
            .par_iter_mut()
            .with_min_len(MIN_PAR_SIZE)
            .zip((0..final_v.len()).into_par_iter())
            .for_each(|(row, i)| {
                set_val!(row, self.final_v, final_v[i] as u64);
                set_val!(row, self.final_t, final_t[i] as u64);
            });

        Ok(final_table)
    }
}
