use std::{collections::HashMap, marker::PhantomData, mem::MaybeUninit};

use ceno_emul::{Addr, Cycle, Platform};
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
    platform: Platform,
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
                len: NVRAM::len(&cb.cs.platform),
            },
            init_table,
        )?;
        cb.r_table_record(
            || "final_table",
            NVRAM::RAM_TYPE,
            SetTableSpec {
                addr_type: SetTableAddrType::FixedAddr,
                len: NVRAM::len(&cb.cs.platform),
            },
            final_table,
        )?;

        Ok(Self {
            init_v,
            final_v,
            addr,
            final_cycle,
            phantom: PhantomData,
            platform: cb.cs.platform,
        })
    }

    pub fn gen_init_state<F: SmallField>(
        &self,
        num_fixed: usize,
        init_mem: &[MemInitRecord],
    ) -> RowMajorMatrix<F> {
        assert!(
            NVRAM::len(&self.platform).is_power_of_two(),
            "{} len {} must be a power of 2",
            NVRAM::name(),
            NVRAM::len(&self.platform)
        );

        let mut init_table = RowMajorMatrix::<F>::new(NVRAM::len(&self.platform), num_fixed);
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
        let mut final_table = RowMajorMatrix::<F>::new(NVRAM::len(&self.platform), num_witness);

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
    platform: Platform,
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
                len: NVRAM::len(&cb.cs.platform),
            },
            init_table,
        )?;
        cb.r_table_record(
            || "final_table",
            NVRAM::RAM_TYPE,
            SetTableSpec {
                addr_type: SetTableAddrType::FixedAddr,
                len: NVRAM::len(&cb.cs.platform),
            },
            final_table,
        )?;

        Ok(Self {
            addr,
            final_cycle,
            phantom: PhantomData,
            platform: cb.cs.platform,
        })
    }

    /// assign to fixed address
    pub fn gen_init_state<F: SmallField>(
        &self,
        num_fixed: usize,
        io_addrs: &[Addr],
    ) -> RowMajorMatrix<F> {
        assert!(NVRAM::len(&self.platform).is_power_of_two());

        let mut init_table = RowMajorMatrix::<F>::new(NVRAM::len(&self.platform), num_fixed);
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
        let mut final_table = RowMajorMatrix::<F>::new(NVRAM::len(&self.platform), num_witness);

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
    platform: Platform,
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

        let init_table = [
            vec![(DVRAM::RAM_TYPE as usize).into()],
            vec![addr.expr()],
            vec![Expression::ZERO],
            vec![Expression::ZERO], // Initial cycle.
        ]
        .concat();

        let final_table = [
            // a v t
            vec![(DVRAM::RAM_TYPE as usize).into()],
            vec![addr.expr()],
            final_v.iter().map(|v| v.expr()).collect_vec(),
            vec![final_cycle.expr()],
        ]
        .concat();

        cb.w_table_record(
            || "init_table",
            DVRAM::RAM_TYPE,
            SetTableSpec {
                addr_type: SetTableAddrType::DynamicAddr(DynamicAddr {
                    addr_witin_id: addr.id.into(),
                    offset: DVRAM::offset_addr(&cb.cs.platform),
                }),
                len: DVRAM::max_len(&cb.cs.platform),
            },
            init_table,
        )?;
        cb.r_table_record(
            || "final_table",
            DVRAM::RAM_TYPE,
            SetTableSpec {
                addr_type: SetTableAddrType::DynamicAddr(DynamicAddr {
                    addr_witin_id: addr.id.into(),
                    offset: DVRAM::offset_addr(&cb.cs.platform),
                }),
                len: DVRAM::max_len(&cb.cs.platform),
            },
            final_table,
        )?;

        Ok(Self {
            addr,
            final_v,
            final_cycle,
            phantom: PhantomData,
            platform: cb.cs.platform,
        })
    }

    /// TODO consider taking RowMajorMatrix as argument to save allocations.
    pub fn assign_instances<F: SmallField>(
        &self,
        num_witness: usize,
        final_mem: &[MemFinalRecord],
    ) -> Result<RowMajorMatrix<F>, ZKVMError> {
        let accessed_addrs = final_mem
            .iter()
            .cloned()
            .map(|record| (record.addr, record))
            .collect::<HashMap<_, _>>();
        assert!(DVRAM::max_len(&self.platform).is_power_of_two());
        let mut final_table = RowMajorMatrix::<F>::new(DVRAM::max_len(&self.platform), num_witness);

        final_table
            .par_iter_mut()
            .with_min_len(MIN_PAR_SIZE)
            .enumerate()
            .for_each(|(i, row)| {
                let addr = DVRAM::addr(&self.platform, i);
                set_val!(row, self.addr, addr as u64);
                if let Some(rec) = accessed_addrs.get(&addr) {
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
                } else {
                    // Assign value limbs.
                    self.final_v.iter().for_each(|limb| {
                        set_val!(row, limb, 0u64);
                    });
                    set_val!(row, self.final_cycle, 0_u64);
                }
            });

        Ok(final_table)
    }
}

#[allow(dead_code)]
/// DynUnConstrainRamTableConfig with unconstrain init value and final value
/// dynamic address as witin, relied on augment of knowledge to prove address form
/// do not check init_value
/// TODO implement DynUnConstrainRamTableConfig
#[derive(Clone, Debug)]
pub struct DynUnConstrainRamTableConfig<RAM: DynVolatileRamTable + Send + Sync + Clone> {
    addr: WitIn,

    init_v: Vec<WitIn>,

    final_v: Vec<WitIn>,
    final_cycle: WitIn,

    phantom: PhantomData<RAM>,
}
