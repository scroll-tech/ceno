use std::{marker::PhantomData, mem::MaybeUninit};

use ceno_emul::{Addr, Cycle};
use ff_ext::ExtensionField;
use goldilocks::SmallField;
use itertools::Itertools;
use rayon::iter::{IndexedParallelIterator, IntoParallelIterator, ParallelIterator};

use crate::{
    circuit_builder::{CircuitBuilder, DynamicAddr, SetTableAddrType, SetTableSpec},
    error::ZKVMError,
    expression::{Expression, Fixed, ToExpr, WitIn},
    instructions::riscv::constants::{LIMB_BITS, LIMB_MASK},
    scheme::constants::MIN_PAR_SIZE,
    set_fixed_val, set_val,
    structs::ProgramParams,
    witness::RowMajorMatrix,
};

use super::{
    MemInitRecord,
    ram_circuit::{DynVolatileRamTable, MemFinalRecord, NonVolatileTable},
};

/// define a non-volatile memory with init value
#[derive(Clone, Debug)]
pub struct NonVolatileTableConfig<NVRAM: NonVolatileTable + Send + Sync + Clone> {
    init_v: Vec<Fixed>,
    addr: Fixed,

    final_v: Option<Vec<WitIn>>,
    final_cycle: WitIn,

    phantom: PhantomData<NVRAM>,
    params: ProgramParams,
}

impl<NVRAM: NonVolatileTable + Send + Sync + Clone> NonVolatileTableConfig<NVRAM> {
    pub fn construct_circuit<E: ExtensionField>(
        cb: &mut CircuitBuilder<E>,
    ) -> Result<Self, ZKVMError> {
        let init_v = (0..NVRAM::V_LIMBS)
            .map(|i| cb.create_fixed(|| format!("init_v_limb_{i}")))
            .collect::<Result<Vec<Fixed>, ZKVMError>>()?;
        let addr = cb.create_fixed(|| "addr")?;

        let final_cycle = cb.create_witin(|| "final_cycle");
        let final_v = if NVRAM::WRITABLE {
            Some(
                (0..NVRAM::V_LIMBS)
                    .map(|i| cb.create_witin(|| format!("final_v_limb_{i}")))
                    .collect::<Vec<WitIn>>(),
            )
        } else {
            None
        };

        let init_table = [
            vec![(NVRAM::RAM_TYPE as usize).into()],
            vec![Expression::Fixed(addr)],
            init_v.iter().map(|v| v.expr()).collect_vec(),
            vec![Expression::ZERO], // Initial cycle.
        ]
        .concat();

        let final_table = [
            // a v t
            vec![(NVRAM::RAM_TYPE as usize).into()],
            vec![Expression::Fixed(addr)],
            final_v
                .as_ref()
                .map(|v_limb| v_limb.iter().map(|v| v.expr()).collect_vec())
                .unwrap_or_else(|| init_v.iter().map(|v| v.expr()).collect_vec()),
            vec![final_cycle.expr()],
        ]
        .concat();

        cb.w_table_record(
            || "init_table",
            NVRAM::RAM_TYPE,
            SetTableSpec {
                addr_type: SetTableAddrType::FixedAddr,
                len: NVRAM::len(&cb.params),
            },
            init_table,
        )?;
        cb.r_table_record(
            || "final_table",
            NVRAM::RAM_TYPE,
            SetTableSpec {
                addr_type: SetTableAddrType::FixedAddr,
                len: NVRAM::len(&cb.params),
            },
            final_table,
        )?;

        Ok(Self {
            init_v,
            final_v,
            addr,
            final_cycle,
            phantom: PhantomData,
            params: cb.params.clone(),
        })
    }

    pub fn gen_init_state<F: SmallField>(
        &self,
        num_fixed: usize,
        init_mem: &[MemInitRecord],
    ) -> RowMajorMatrix<F> {
        assert!(
            NVRAM::len(&self.params).is_power_of_two(),
            "{} len {} must be a power of 2",
            NVRAM::name(),
            NVRAM::len(&self.params)
        );

        let mut init_table = RowMajorMatrix::<F>::new(NVRAM::len(&self.params), num_fixed);
        assert_eq!(init_table.num_padding_instances(), 0);

        init_table
            .par_iter_mut()
            .with_min_len(MIN_PAR_SIZE)
            .zip_eq(init_mem.into_par_iter())
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
        final_mem: &[MemFinalRecord],
    ) -> Result<RowMajorMatrix<F>, ZKVMError> {
        let mut final_table = RowMajorMatrix::<F>::new(NVRAM::len(&self.params), num_witness);

        final_table
            .par_iter_mut()
            .with_min_len(MIN_PAR_SIZE)
            .zip_eq(final_mem.into_par_iter())
            .for_each(|(row, rec)| {
                if let Some(final_v) = &self.final_v {
                    if final_v.len() == 1 {
                        // Assign value directly.
                        set_val!(row, final_v[0], rec.value as u64);
                    } else {
                        // Assign value limbs.
                        final_v.iter().enumerate().for_each(|(l, limb)| {
                            let val = (rec.value >> (l * LIMB_BITS)) & LIMB_MASK;
                            set_val!(row, limb, val as u64);
                        });
                    }
                }
                set_val!(row, self.final_cycle, rec.cycle);
            });

        Ok(final_table)
    }
}

/// define public io
/// init value set by instance
#[derive(Clone, Debug)]
pub struct PubIOTableConfig<NVRAM: NonVolatileTable + Send + Sync + Clone> {
    addr: Fixed,

    final_cycle: WitIn,

    phantom: PhantomData<NVRAM>,
    params: ProgramParams,
}

impl<NVRAM: NonVolatileTable + Send + Sync + Clone> PubIOTableConfig<NVRAM> {
    pub fn construct_circuit<E: ExtensionField>(
        cb: &mut CircuitBuilder<E>,
    ) -> Result<Self, ZKVMError> {
        assert!(!NVRAM::WRITABLE);
        let init_v = cb.query_public_io()?;
        let addr = cb.create_fixed(|| "addr")?;

        let final_cycle = cb.create_witin(|| "final_cycle");

        let init_table = [
            vec![(NVRAM::RAM_TYPE as usize).into()],
            vec![Expression::Fixed(addr)],
            vec![init_v.expr()],
            vec![Expression::ZERO], // Initial cycle.
        ]
        .concat();

        let final_table = [
            // a v t
            vec![(NVRAM::RAM_TYPE as usize).into()],
            vec![Expression::Fixed(addr)],
            vec![init_v.expr()],
            vec![final_cycle.expr()],
        ]
        .concat();

        cb.w_table_record(
            || "init_table",
            NVRAM::RAM_TYPE,
            SetTableSpec {
                addr_type: SetTableAddrType::FixedAddr,
                len: NVRAM::len(&cb.params),
            },
            init_table,
        )?;
        cb.r_table_record(
            || "final_table",
            NVRAM::RAM_TYPE,
            SetTableSpec {
                addr_type: SetTableAddrType::FixedAddr,
                len: NVRAM::len(&cb.params),
            },
            final_table,
        )?;

        Ok(Self {
            addr,
            final_cycle,
            phantom: PhantomData,
            params: cb.params.clone(),
        })
    }

    /// assign to fixed address
    pub fn gen_init_state<F: SmallField>(
        &self,
        num_fixed: usize,
        io_addrs: &[Addr],
    ) -> RowMajorMatrix<F> {
        assert!(NVRAM::len(&self.params).is_power_of_two());

        let mut init_table = RowMajorMatrix::<F>::new(NVRAM::len(&self.params), num_fixed);
        assert_eq!(init_table.num_padding_instances(), 0);

        init_table
            .par_iter_mut()
            .with_min_len(MIN_PAR_SIZE)
            .zip_eq(io_addrs.into_par_iter())
            .for_each(|(row, addr)| {
                set_fixed_val!(row, self.addr, (*addr as u64).into());
            });
        init_table
    }

    /// TODO consider taking RowMajorMatrix as argument to save allocations.
    pub fn assign_instances<F: SmallField>(
        &self,
        num_witness: usize,
        final_cycles: &[Cycle],
    ) -> Result<RowMajorMatrix<F>, ZKVMError> {
        let mut final_table = RowMajorMatrix::<F>::new(NVRAM::len(&self.params), num_witness);

        final_table
            .par_iter_mut()
            .with_min_len(MIN_PAR_SIZE)
            .zip_eq(final_cycles.into_par_iter())
            .for_each(|(row, &cycle)| {
                set_val!(row, self.final_cycle, cycle);
            });

        Ok(final_table)
    }
}

/// volatile with all init value as 0
/// dynamic address as witin, relied on augment of knowledge to prove address form
#[derive(Clone, Debug)]
pub struct DynVolatileRamTableConfig<DVRAM: DynVolatileRamTable + Send + Sync + Clone> {
    addr: WitIn,

    final_v: Vec<WitIn>,
    final_cycle: WitIn,

    phantom: PhantomData<DVRAM>,
    params: ProgramParams,
}

impl<DVRAM: DynVolatileRamTable + Send + Sync + Clone> DynVolatileRamTableConfig<DVRAM> {
    pub fn construct_circuit<E: ExtensionField>(
        cb: &mut CircuitBuilder<E>,
    ) -> Result<Self, ZKVMError> {
        let addr = cb.create_witin(|| "addr");

        let final_v = (0..DVRAM::V_LIMBS)
            .map(|i| cb.create_witin(|| format!("final_v_limb_{i}")))
            .collect::<Vec<WitIn>>();
        let final_cycle = cb.create_witin(|| "final_cycle");

        let final_expr = final_v.iter().map(|v| v.expr()).collect_vec();
        let init_expr = if DVRAM::ZERO_INIT {
            vec![Expression::ZERO; DVRAM::V_LIMBS]
        } else {
            final_expr.clone()
        };

        let init_table = [
            vec![(DVRAM::RAM_TYPE as usize).into()],
            vec![addr.expr()],
            init_expr,
            vec![Expression::ZERO], // Initial cycle.
        ]
        .concat();

        let final_table = [
            // a v t
            vec![(DVRAM::RAM_TYPE as usize).into()],
            vec![addr.expr()],
            final_expr,
            vec![final_cycle.expr()],
        ]
        .concat();

        cb.w_table_record(
            || "init_table",
            DVRAM::RAM_TYPE,
            SetTableSpec {
                addr_type: SetTableAddrType::DynamicAddr(DynamicAddr {
                    addr_witin_id: addr.id.into(),
                    offset: DVRAM::offset_addr(&cb.params),
                }),
                len: DVRAM::max_len(&cb.params),
            },
            init_table,
        )?;
        cb.r_table_record(
            || "final_table",
            DVRAM::RAM_TYPE,
            SetTableSpec {
                addr_type: SetTableAddrType::DynamicAddr(DynamicAddr {
                    addr_witin_id: addr.id.into(),
                    offset: DVRAM::offset_addr(&cb.params),
                }),
                len: DVRAM::max_len(&cb.params),
            },
            final_table,
        )?;

        Ok(Self {
            addr,
            final_v,
            final_cycle,
            phantom: PhantomData,
            params: cb.params.clone(),
        })
    }

    /// TODO consider taking RowMajorMatrix as argument to save allocations.
    pub fn assign_instances<F: SmallField>(
        &self,
        num_witness: usize,
        final_mem: &[MemFinalRecord],
    ) -> Result<RowMajorMatrix<F>, ZKVMError> {
        assert!(final_mem.len() <= DVRAM::max_len(&self.params));
        assert!(DVRAM::max_len(&self.params).is_power_of_two());
        let mut final_table =
            RowMajorMatrix::<F>::new(final_mem.len().next_power_of_two(), num_witness);

        final_table
            .par_iter_mut()
            .with_min_len(MIN_PAR_SIZE)
            .zip(final_mem.into_par_iter())
            .for_each(|(row, rec)| {
                set_val!(row, self.addr, rec.addr as u64);
                if self.final_v.len() == 1 {
                    // Assign value directly.
                    set_val!(row, self.final_v[0], rec.value as u64);
                } else {
                    // Assign value limbs.
                    self.final_v.iter().enumerate().for_each(|(l, limb)| {
                        let val = (rec.value >> (l * LIMB_BITS)) & LIMB_MASK;
                        set_val!(row, limb, val as u64);
                    });
                }
                set_val!(row, self.final_cycle, rec.cycle);
            });

        // set padding with well-form address
        if final_mem.len().next_power_of_two() - final_mem.len() > 0 {
            let paddin_entry_start = final_mem.len();
            final_table
                .par_iter_mut()
                .skip(final_mem.len())
                .enumerate()
                .with_min_len(MIN_PAR_SIZE)
                .for_each(|(i, row)| {
                    // Assign value limbs.
                    self.final_v.iter().for_each(|limb| {
                        set_val!(row, limb, 0u64);
                    });
                    set_val!(
                        row,
                        self.addr,
                        DVRAM::addr(&self.params, paddin_entry_start + i) as u64
                    );
                    set_val!(row, self.final_cycle, 0_u64);
                });
        }

        Ok(final_table)
    }
}
