use std::{marker::PhantomData, sync::Arc};

use ceno_emul::{Addr, Cycle};
use ff_ext::ExtensionField;
use goldilocks::SmallField;
use itertools::Itertools;
use rayon::iter::{IndexedParallelIterator, IntoParallelIterator, ParallelIterator};

use crate::{
    circuit_builder::{CircuitBuilder, DynamicAddr, SetTableAddrType, SetTableSpec},
    error::ZKVMError,
    expression::{Expression, Fixed, ToExpr, WitIn},
    instructions::{
        InstancePaddingStrategy,
        riscv::constants::{LIMB_BITS, LIMB_MASK},
    },
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

        let mut init_table = RowMajorMatrix::<F>::new(
            NVRAM::len(&self.params),
            num_fixed,
            InstancePaddingStrategy::Default,
        );
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
        let mut final_table = RowMajorMatrix::<F>::new(
            NVRAM::len(&self.params),
            num_witness,
            InstancePaddingStrategy::Default,
        );

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

        let mut init_table = RowMajorMatrix::<F>::new(
            NVRAM::len(&self.params),
            num_fixed,
            InstancePaddingStrategy::Default,
        );
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
        let mut final_table = RowMajorMatrix::<F>::new(
            NVRAM::len(&self.params),
            num_witness,
            InstancePaddingStrategy::Default,
        );

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

        let params = self.params.clone();
        let addr_column = self.addr.id as u64;
        let padding_fn = move |row: u64, col: u64| {
            if col == addr_column {
                DVRAM::addr(&params, row as usize) as u64
            } else {
                0u64
            }
        };

        let mut final_table = RowMajorMatrix::<F>::new(
            final_mem.len(),
            num_witness,
            InstancePaddingStrategy::Custom(Arc::new(padding_fn)),
        );

        final_table
            .par_iter_mut()
            .with_min_len(MIN_PAR_SIZE)
            .zip(final_mem.into_par_iter())
            .enumerate()
            .for_each(|(i, (row, rec))| {
                assert_eq!(rec.addr, DVRAM::addr(&self.params, i));
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

        Ok(final_table)
    }
}

#[cfg(test)]
mod tests {
    use std::iter::successors;

    use crate::{
        circuit_builder::{CircuitBuilder, ConstraintSystem},
        structs::ProgramParams,
        tables::{DynVolatileRamTable, HintsCircuit, HintsTable, MemFinalRecord, TableCircuit},
        utils::next_pow2_instance_padding,
        witness::LkMultiplicity,
    };

    use ceno_emul::WORD_SIZE;
    use goldilocks::{Goldilocks as F, GoldilocksExt2 as E};
    use itertools::Itertools;

    #[test]
    fn test_well_formed_address_padding() {
        let mut cs = ConstraintSystem::<E>::new(|| "riscv");
        let mut cb = CircuitBuilder::new(&mut cs);
        let config = HintsCircuit::construct_circuit(&mut cb).unwrap();

        let def_params = ProgramParams::default();
        let lkm = LkMultiplicity::default().into_finalize_result();

        // ensure non-empty padding is required
        let some_non_2_pow = 26;
        let input = (0..some_non_2_pow)
            .map(|i| MemFinalRecord {
                addr: HintsTable::addr(&def_params, i),
                cycle: 0,
                value: 0,
            })
            .collect_vec();
        let wit =
            HintsCircuit::<E>::assign_instances(&config, cb.cs.num_witin as usize, &lkm, &input)
                .unwrap();

        let addr_column = cb
            .cs
            .witin_namespace_map
            .iter()
            .position(|name| name == "riscv/RAM_Memory_HintsTable/addr")
            .unwrap();

        let addr_padded_view = wit.column_padded(addr_column);
        // Expect addresses to proceed consecutively inside the padding as well
        let expected = successors(Some(addr_padded_view[0]), |idx| {
            Some(*idx + F::from(WORD_SIZE as u64))
        })
        .take(next_pow2_instance_padding(wit.num_instances()))
        .collect::<Vec<_>>();

        assert_eq!(addr_padded_view, expected)
    }
}
