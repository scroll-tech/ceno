use std::{marker::PhantomData, mem::MaybeUninit};

use ff_ext::ExtensionField;
use goldilocks::SmallField;
use itertools::Itertools;
use rayon::iter::{IndexedParallelIterator, IntoParallelIterator, ParallelIterator};

use crate::{
    circuit_builder::{CircuitBuilder, SetTableAddrType, SetTableSpec},
    error::ZKVMError,
    expression::{Expression, Fixed, ToExpr, WitIn},
    instructions::riscv::constants::{LIMB_BITS, LIMB_MASK},
    scheme::constants::MIN_PAR_SIZE,
    set_fixed_val, set_val,
    witness::RowMajorMatrix,
};

use super::{
    MemInitRecord,
    ram_circuit::{DynVolatileRamTable, MemFinalRecord, NonVolatileTable},
};

/// define a non-volatile memory with init value
#[derive(Clone, Debug)]
pub struct NonVolatileTableConfig {
    init_v: Vec<Fixed>,
    addr: Fixed,

    final_v: Option<Vec<WitIn>>,
    final_cycle: WitIn,

    nvt: NonVolatileTable,
}

impl NonVolatileTableConfig {
    pub fn construct_circuit<E: ExtensionField>(
        nvt: NonVolatileTable,
        cb: &mut CircuitBuilder<E>,
    ) -> Result<Self, ZKVMError> {
        let init_v = (0..nvt.v_limbs())
            .map(|i| cb.create_fixed(|| format!("init_v_limb_{i}")))
            .collect::<Result<Vec<Fixed>, ZKVMError>>()?;
        let addr = cb.create_fixed(|| "addr")?;

        let final_cycle = cb.create_witin(|| "final_cycle");
        let final_v = if nvt.writable() {
            Some(
                (0..nvt.v_limbs())
                    .map(|i| cb.create_witin(|| format!("final_v_limb_{i}")))
                    .collect::<Vec<WitIn>>(),
            )
        } else {
            None
        };

        let init_table = [
            vec![(nvt.ram_type as usize).into()],
            vec![Expression::Fixed(addr)],
            init_v.iter().map(|v| v.expr()).collect_vec(),
            vec![Expression::ZERO], // Initial cycle.
        ]
        .concat();

        let final_table = [
            // a v t
            vec![(nvt.ram_type() as usize).into()],
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
            nvt.ram_type(),
            SetTableSpec {
                addr_type: SetTableAddrType::FixedAddr,
                addr_witin_id: None,
                offset: nvt.offset_addr(),
                len: nvt.len(),
            },
            init_table,
        )?;
        cb.r_table_record(
            || "final_table",
            nvt.ram_type(),
            SetTableSpec {
                addr_type: SetTableAddrType::FixedAddr,
                addr_witin_id: None,
                offset: nvt.offset_addr(),
                len: nvt.len(),
            },
            final_table,
        )?;

        Ok(Self {
            init_v,
            final_v,
            addr,
            final_cycle,
            // phantom: PhantomData,
            nvt,
        })
    }

    /// assign to fixed instance
    /// assume init_mem sorted by address in increasing order
    pub fn gen_init_state<F: SmallField>(
        &self,
        num_fixed: usize,
        init_mem: &[MemInitRecord],
    ) -> RowMajorMatrix<F> {
        assert!(self.nvt.len().is_power_of_two());
        assert!(init_mem.len() <= self.nvt.len());

        // for ram in memory offline check
        let mut init_table = RowMajorMatrix::<F>::new(self.nvt.len(), num_fixed);
        assert_eq!(init_table.num_padding_instances(), 0);

        init_table
            .par_iter_mut()
            .with_min_len(MIN_PAR_SIZE)
            .zip(init_mem.into_par_iter())
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

        // set padding with well-form address with 0 value
        if self.nvt.len() - init_mem.len() > 0 {
            let paddin_entry_start = init_mem.len();
            init_table
                .par_iter_mut()
                .skip(init_mem.len())
                .enumerate()
                .with_min_len(MIN_PAR_SIZE)
                .for_each(|(i, row)| {
                    // set value limb to 0
                    self.init_v.iter().for_each(|limb| {
                        set_fixed_val!(row, limb, 0u64.into());
                    });
                    set_fixed_val!(
                        row,
                        self.addr,
                        (self.nvt.addr(paddin_entry_start + i) as u64).into()
                    );
                });
        }
        init_table
    }

    /// TODO consider taking RowMajorMatrix as argument to save allocations.
    pub fn assign_instances<F: SmallField>(
        &self,
        num_witness: usize,
        final_mem: &[MemFinalRecord],
    ) -> Result<RowMajorMatrix<F>, ZKVMError> {
        assert!(final_mem.len() <= self.nvt.len());
        let mut final_table = RowMajorMatrix::<F>::new(self.nvt.len(), num_witness);

        final_table
            .par_iter_mut()
            .with_min_len(MIN_PAR_SIZE)
            .zip(final_mem.into_par_iter())
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

        if self.nvt.len() - final_mem.len() > 0 {
            final_table
                .par_iter_mut()
                .skip(final_mem.len())
                .with_min_len(MIN_PAR_SIZE)
                .for_each(|row| {
                    // set cycle to 0
                    set_val!(row, self.final_cycle, 0u64);
                });
        }

        Ok(final_table)
    }
}

/// define public io
/// init value set by instance
#[derive(Clone, Debug)]
pub struct PubIOTableConfig {
    addr: Fixed,

    final_cycle: WitIn,

    // phantom: PhantomData<NVRAM>,
    nvt: NonVolatileTable,
}

impl PubIOTableConfig {
    pub fn construct_circuit<E: ExtensionField>(
        nvt: NonVolatileTable,
        cb: &mut CircuitBuilder<E>,
    ) -> Result<Self, ZKVMError> {
        assert!(!nvt.writable());
        let init_v = cb.query_public_io()?;
        let addr = cb.create_fixed(|| "addr")?;

        let final_cycle = cb.create_witin(|| "final_cycle");

        let init_table = [
            vec![(nvt.ram_type() as usize).into()],
            vec![Expression::Fixed(addr)],
            vec![init_v.expr()],
            vec![Expression::ZERO], // Initial cycle.
        ]
        .concat();

        let final_table = [
            // a v t
            vec![(nvt.ram_type() as usize).into()],
            vec![Expression::Fixed(addr)],
            vec![init_v.expr()],
            vec![final_cycle.expr()],
        ]
        .concat();

        cb.w_table_record(
            || "init_table",
            nvt.ram_type(),
            SetTableSpec {
                addr_type: SetTableAddrType::FixedAddr,
                addr_witin_id: None,
                offset: nvt.offset_addr(),
                len: nvt.len(),
            },
            init_table,
        )?;
        cb.r_table_record(
            || "final_table",
            nvt.ram_type(),
            SetTableSpec {
                addr_type: SetTableAddrType::FixedAddr,
                addr_witin_id: None,
                offset: nvt.offset_addr(),
                len: nvt.len(),
            },
            final_table,
        )?;

        Ok(Self {
            addr,
            final_cycle,
            // phantom: PhantomData,
            nvt,
        })
    }

    /// assign to fixed address
    pub fn gen_init_state<F: SmallField>(&self, num_fixed: usize) -> RowMajorMatrix<F> {
        assert!(self.nvt.len().is_power_of_two());

        // for ram in memory offline check
        let mut init_table = RowMajorMatrix::<F>::new(self.nvt.len(), num_fixed);
        assert_eq!(init_table.num_padding_instances(), 0);

        init_table
            .par_iter_mut()
            .enumerate()
            .with_min_len(MIN_PAR_SIZE)
            .for_each(|(i, row)| {
                set_fixed_val!(row, self.addr, (self.nvt.addr(i) as u64).into());
            });
        init_table
    }

    /// TODO consider taking RowMajorMatrix as argument to save allocations.
    pub fn assign_instances<F: SmallField>(
        &self,
        num_witness: usize,
        final_mem: &[MemFinalRecord],
    ) -> Result<RowMajorMatrix<F>, ZKVMError> {
        assert!(final_mem.len() == self.nvt.len());
        let mut final_table = RowMajorMatrix::<F>::new(self.nvt.len(), num_witness);

        final_table
            .par_iter_mut()
            .with_min_len(MIN_PAR_SIZE)
            .zip(final_mem.into_par_iter())
            .for_each(|(row, rec)| {
                set_val!(row, self.final_cycle, rec.cycle);
            });

        Ok(final_table)
    }
}

/// volatile with all init value as 0
/// dynamic address as witin, relied on augment of knowledge to prove address form
#[derive(Clone, Debug)]
pub struct DynVolatileRamTableConfig {
    addr: WitIn,

    final_v: Vec<WitIn>,
    final_cycle: WitIn,

    // phantom: PhantomData<DVRAM>,
    dvram: DynVolatileRamTable,
}

impl DynVolatileRamTableConfig {
    pub fn construct_circuit<E: ExtensionField>(
        dvram: DynVolatileRamTable,
        cb: &mut CircuitBuilder<E>,
    ) -> Result<Self, ZKVMError> {
        let addr = cb.create_witin(|| "addr");

        let final_v = (0..dvram.v_limbs())
            .map(|i| cb.create_witin(|| format!("final_v_limb_{i}")))
            .collect::<Vec<WitIn>>();
        let final_cycle = cb.create_witin(|| "final_cycle");

        let init_table = [
            vec![(dvram.ram_type() as usize).into()],
            vec![addr.expr()],
            vec![Expression::ZERO],
            vec![Expression::ZERO], // Initial cycle.
        ]
        .concat();

        let final_table = [
            // a v t
            vec![(dvram.ram_type() as usize).into()],
            vec![addr.expr()],
            final_v.iter().map(|v| v.expr()).collect_vec(),
            vec![final_cycle.expr()],
        ]
        .concat();

        cb.w_table_record(
            || "init_table",
            dvram.ram_type(),
            SetTableSpec {
                addr_type: SetTableAddrType::DynamicAddr,
                addr_witin_id: Some(addr.id.into()),
                offset: dvram.offset_addr(),
                len: dvram.max_len(),
            },
            init_table,
        )?;
        cb.r_table_record(
            || "final_table",
            dvram.ram_type(),
            SetTableSpec {
                addr_type: SetTableAddrType::DynamicAddr,
                addr_witin_id: Some(addr.id.into()),
                offset: dvram.offset_addr(),
                len: dvram.max_len(),
            },
            final_table,
        )?;

        Ok(Self {
            addr,
            final_v,
            final_cycle,
            // phantom: PhantomData,
            dvram,
        })
    }

    /// TODO consider taking RowMajorMatrix as argument to save allocations.
    pub fn assign_instances<F: SmallField>(
        &self,
        num_witness: usize,
        final_mem: &[MemFinalRecord],
    ) -> Result<RowMajorMatrix<F>, ZKVMError> {
        assert!(final_mem.len() <= self.dvram().max_len());
        assert!(self.dvram.max_len().is_power_of_two());
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
                        self.dvram.addr(paddin_entry_start + i) as u64
                    );
                });
        }

        Ok(final_table)
    }
}

#[allow(dead_code)]
/// DynUnConstrainRamTableConfig with unconstrain init value and final value
/// dynamic address as witin, relied on augment of knowledge to prove address form
/// do not check init_value
/// TODO implement DynUnConstrainRamTableConfig
#[derive(Clone, Debug)]
pub struct DynUnConstrainRamTableConfig {
    addr: WitIn,

    init_v: Vec<WitIn>,

    final_v: Vec<WitIn>,
    final_cycle: WitIn,

    // phantom: PhantomData<RAM>,
    dvram: DynVolatileRamTable,
}
