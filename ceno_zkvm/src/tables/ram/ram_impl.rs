use ceno_emul::{Addr, Cycle, WORD_SIZE};
use either::Either;
use ff_ext::{ExtensionField, SmallField};
use gkr_iop::error::CircuitBuilderError;
use itertools::Itertools;
use rayon::iter::{IndexedParallelIterator, IntoParallelRefMutIterator, ParallelIterator};
use std::{marker::PhantomData, ops::Neg, sync::Arc};
use witness::{
    InstancePaddingStrategy, RowMajorMatrix, next_pow2_instance_padding, set_fixed_val, set_val,
};

use super::{
    MemInitRecord,
    ram_circuit::{DynVolatileRamTable, MemFinalRecord, NonVolatileTable},
};
use crate::{
    chip_handler::general::PublicIOQuery,
    circuit_builder::{CircuitBuilder, SetTableSpec},
    e2e::RAMRecord,
    instructions::riscv::constants::{LIMB_BITS, LIMB_MASK},
    structs::ProgramParams,
};
use ff_ext::FieldInto;
use multilinear_extensions::{
    Expression, Fixed, StructuralWitIn, StructuralWitInType, ToExpr, WitIn,
};
use p3::field::FieldAlgebra;
use rayon::prelude::{ParallelSlice, ParallelSliceMut};

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
        params: &ProgramParams,
    ) -> Result<Self, CircuitBuilderError> {
        let init_v = (0..NVRAM::V_LIMBS)
            .map(|i| cb.create_fixed(|| format!("init_v_limb_{i}")))
            .collect_vec();
        let addr = cb.create_fixed(|| "addr");

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
                len: Some(NVRAM::len(params)),
                structural_witins: vec![],
            },
            init_table,
        )?;
        cb.r_table_record(
            || "final_table",
            NVRAM::RAM_TYPE,
            SetTableSpec {
                len: Some(NVRAM::len(params)),
                structural_witins: vec![],
            },
            final_table,
        )?;

        Ok(Self {
            init_v,
            final_v,
            addr,
            final_cycle,
            phantom: PhantomData,
            params: params.clone(),
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
            .par_rows_mut()
            .zip_eq(init_mem)
            .for_each(|(row, rec)| {
                if self.init_v.len() == 1 {
                    // Assign value directly.
                    set_fixed_val!(row, self.init_v[0], (rec.value as u64).into_f());
                } else {
                    // Assign value limbs.
                    self.init_v.iter().enumerate().for_each(|(l, limb)| {
                        let val = (rec.value >> (l * LIMB_BITS)) & LIMB_MASK;
                        set_fixed_val!(row, limb, (val as u64).into_f());
                    });
                }
                set_fixed_val!(row, self.addr, (rec.addr as u64).into_f());
            });

        init_table
    }

    /// TODO consider taking RowMajorMatrix as argument to save allocations.
    pub fn assign_instances<F: SmallField>(
        &self,
        num_witin: usize,
        num_structural_witin: usize,
        final_mem: &[MemFinalRecord],
    ) -> Result<[RowMajorMatrix<F>; 2], CircuitBuilderError> {
        assert_eq!(num_structural_witin, 0);
        let mut final_table = RowMajorMatrix::<F>::new(
            NVRAM::len(&self.params),
            num_witin,
            InstancePaddingStrategy::Default,
        );

        final_table
            .par_rows_mut()
            .zip_eq(final_mem)
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

        Ok([final_table, RowMajorMatrix::empty()])
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
        params: &ProgramParams,
    ) -> Result<Self, CircuitBuilderError> {
        assert!(!NVRAM::WRITABLE);
        let init_v = cb.query_public_io()?;
        let addr = cb.create_fixed(|| "addr");

        let final_cycle = cb.create_witin(|| "final_cycle");

        let init_table = [
            vec![(NVRAM::RAM_TYPE as usize).into()],
            vec![Expression::Fixed(addr)],
            init_v.iter().map(|v| v.expr_as_instance()).collect_vec(),
            vec![Expression::ZERO], // Initial cycle.
        ]
        .concat();

        let final_table = [
            // a v t
            vec![(NVRAM::RAM_TYPE as usize).into()],
            vec![Expression::Fixed(addr)],
            init_v.iter().map(|v| v.expr_as_instance()).collect_vec(),
            vec![final_cycle.expr()],
        ]
        .concat();

        cb.w_table_record(
            || "init_table",
            NVRAM::RAM_TYPE,
            SetTableSpec {
                len: Some(NVRAM::len(params)),
                structural_witins: vec![],
            },
            init_table,
        )?;
        cb.r_table_record(
            || "final_table",
            NVRAM::RAM_TYPE,
            SetTableSpec {
                len: Some(NVRAM::len(params)),
                structural_witins: vec![],
            },
            final_table,
        )?;

        Ok(Self {
            addr,
            final_cycle,
            phantom: PhantomData,
            params: params.clone(),
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
            .par_rows_mut()
            .zip_eq(io_addrs)
            .for_each(|(row, addr)| {
                set_fixed_val!(row, self.addr, (*addr as u64).into_f());
            });
        init_table
    }

    /// TODO consider taking RowMajorMatrix as argument to save allocations.
    pub fn assign_instances<F: SmallField>(
        &self,
        num_witin: usize,
        num_structural_witin: usize,
        final_cycles: &[Cycle],
    ) -> Result<[RowMajorMatrix<F>; 2], CircuitBuilderError> {
        assert_eq!(num_structural_witin, 0);
        let mut final_table = RowMajorMatrix::<F>::new(
            NVRAM::len(&self.params),
            num_witin,
            InstancePaddingStrategy::Default,
        );

        final_table
            .par_rows_mut()
            .zip_eq(final_cycles)
            .for_each(|(row, &cycle)| {
                set_val!(row, self.final_cycle, cycle);
            });

        Ok([final_table, RowMajorMatrix::empty()])
    }
}

/// volatile with all init value as 0
/// dynamic address as witin, relied on augment of knowledge to prove address form
#[derive(Clone, Debug)]
pub struct DynVolatileRamTableConfig<DVRAM: DynVolatileRamTable + Send + Sync + Clone> {
    addr: StructuralWitIn,

    final_v: Vec<WitIn>,
    final_cycle: WitIn,

    phantom: PhantomData<DVRAM>,
    params: ProgramParams,
}

impl<DVRAM: DynVolatileRamTable + Send + Sync + Clone> DynVolatileRamTableConfig<DVRAM> {
    pub fn construct_circuit<E: ExtensionField>(
        cb: &mut CircuitBuilder<E>,
        params: &ProgramParams,
    ) -> Result<Self, CircuitBuilderError> {
        let max_len = DVRAM::max_len(params);
        let addr = cb.create_structural_witin(
            || "addr",
            StructuralWitInType::EqualDistanceSequence {
                max_len,
                offset: DVRAM::offset_addr(params),
                multi_factor: WORD_SIZE,
                descending: DVRAM::DESCENDING,
            },
        );

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
                len: None,
                structural_witins: vec![addr],
            },
            init_table,
        )?;
        cb.r_table_record(
            || "final_table",
            DVRAM::RAM_TYPE,
            SetTableSpec {
                len: None,
                structural_witins: vec![addr],
            },
            final_table,
        )?;

        Ok(Self {
            addr,
            final_v,
            final_cycle,
            phantom: PhantomData,
            params: params.clone(),
        })
    }

    /// TODO consider taking RowMajorMatrix as argument to save allocations.
    pub fn assign_instances<F: SmallField>(
        &self,
        num_witin: usize,
        num_structural_witin: usize,
        final_mem: &[MemFinalRecord],
    ) -> Result<[RowMajorMatrix<F>; 2], CircuitBuilderError> {
        assert!(final_mem.len() <= DVRAM::max_len(&self.params));
        assert!(DVRAM::max_len(&self.params).is_power_of_two());

        let params = self.params.clone();
        let addr_id = self.addr.id as u64;
        let addr_padding_fn = move |row: u64, col: u64| {
            assert_eq!(col, addr_id);
            DVRAM::addr(&params, row as usize) as u64
        };

        let mut witness =
            RowMajorMatrix::<F>::new(final_mem.len(), num_witin, InstancePaddingStrategy::Default);
        let mut structural_witness = RowMajorMatrix::<F>::new(
            final_mem.len(),
            num_structural_witin,
            InstancePaddingStrategy::Custom(Arc::new(addr_padding_fn)),
        );

        witness
            .par_rows_mut()
            .zip(structural_witness.par_rows_mut())
            .zip(final_mem)
            .enumerate()
            .for_each(|(i, ((row, structural_row), rec))| {
                assert_eq!(
                    rec.addr,
                    DVRAM::addr(&self.params, i),
                    "rec.addr {:x} != expected {:x}",
                    rec.addr,
                    DVRAM::addr(&self.params, i),
                );

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

                set_val!(structural_row, self.addr, rec.addr as u64);
            });

        structural_witness.padding_by_strategy();
        Ok([witness, structural_witness])
    }
}

/// volatile with all init value as 0
/// dynamic address as witin, relied on augment of knowledge to prove address form
#[derive(Clone, Debug)]
pub struct DynVolatileRamTableInitConfig<DVRAM: DynVolatileRamTable + Send + Sync + Clone> {
    addr: StructuralWitIn,

    phantom: PhantomData<DVRAM>,
    params: ProgramParams,
}

impl<DVRAM: DynVolatileRamTable + Send + Sync + Clone> DynVolatileRamTableInitConfig<DVRAM> {
    pub fn construct_circuit<E: ExtensionField>(
        cb: &mut CircuitBuilder<E>,
        params: &ProgramParams,
    ) -> Result<Self, CircuitBuilderError> {
        let max_len = DVRAM::max_len(params);
        let addr = cb.create_structural_witin(
            || "addr",
            StructuralWitInType::EqualDistanceSequence {
                max_len,
                offset: DVRAM::offset_addr(params),
                multi_factor: WORD_SIZE,
                descending: DVRAM::DESCENDING,
            },
        );

        assert!(DVRAM::ZERO_INIT);

        let init_expr = vec![Expression::ZERO; DVRAM::V_LIMBS];

        let init_table = [
            vec![(DVRAM::RAM_TYPE as usize).into()],
            vec![addr.expr()],
            init_expr,
            vec![Expression::ZERO], // Initial cycle.
        ]
        .concat();

        cb.w_table_record(
            || "init_table",
            DVRAM::RAM_TYPE,
            SetTableSpec {
                len: None,
                structural_witins: vec![addr],
            },
            init_table,
        )?;

        Ok(Self {
            addr,
            phantom: PhantomData,
            params: params.clone(),
        })
    }

    /// TODO consider taking RowMajorMatrix as argument to save allocations.
    pub fn assign_instances<F: SmallField>(
        &self,
        num_witin: usize,
        num_structural_witin: usize,
        final_mem: &[MemFinalRecord],
    ) -> Result<[RowMajorMatrix<F>; 2], CircuitBuilderError> {
        assert!(final_mem.len() <= DVRAM::max_len(&self.params));
        assert!(DVRAM::max_len(&self.params).is_power_of_two());

        let params = self.params.clone();
        let addr_id = self.addr.id as u64;
        let addr_padding_fn = move |row: u64, col: u64| {
            assert_eq!(col, addr_id);
            DVRAM::addr(&params, row as usize) as u64
        };

        let mut witness =
            RowMajorMatrix::<F>::new(final_mem.len(), num_witin, InstancePaddingStrategy::Default);
        let mut structural_witness = RowMajorMatrix::<F>::new(
            final_mem.len(),
            num_structural_witin,
            InstancePaddingStrategy::Custom(Arc::new(addr_padding_fn)),
        );

        witness
            .par_rows_mut()
            .zip(structural_witness.par_rows_mut())
            .zip(final_mem)
            .enumerate()
            .for_each(|(i, ((row, structural_row), rec))| {
                assert_eq!(
                    rec.addr,
                    DVRAM::addr(&self.params, i),
                    "rec.addr {:x} != expected {:x}",
                    rec.addr,
                    DVRAM::addr(&self.params, i),
                );
                set_val!(structural_row, self.addr, rec.addr as u64);
            });

        structural_witness.padding_by_strategy();
        Ok([witness, structural_witness])
    }
}

/// volatile with all init value as 0
/// dynamic address as witin, relied on augment of knowledge to prove address form
#[derive(Clone, Debug)]
pub struct DynVolatileRamTableFinalConfig<DVRAM: DynVolatileRamTable + Send + Sync + Clone> {
    // addr is subset and could be any form
    // TODO check soundness issue
    addr_subset: WitIn,
    sel: StructuralWitIn,

    final_v: Vec<WitIn>,
    final_cycle: WitIn,

    phantom: PhantomData<DVRAM>,
    params: ProgramParams,
}

impl<DVRAM: DynVolatileRamTable + Send + Sync + Clone> DynVolatileRamTableFinalConfig<DVRAM> {
    pub fn construct_circuit<E: ExtensionField>(
        cb: &mut CircuitBuilder<E>,
        params: &ProgramParams,
    ) -> Result<Self, CircuitBuilderError> {
        let addr_subset = cb.create_witin(|| "addr_subset");

        let sel = cb.create_structural_witin(
            || "sel",
            StructuralWitInType::EqualDistanceSequence {
                max_len: 0,
                offset: DVRAM::offset_addr(params),
                multi_factor: WORD_SIZE,
                descending: DVRAM::DESCENDING,
            },
        );

        let final_v = (0..DVRAM::V_LIMBS)
            .map(|i| cb.create_witin(|| format!("final_v_limb_{i}")))
            .collect::<Vec<WitIn>>();
        let final_cycle = cb.create_witin(|| "final_cycle");

        // R_{local} = sel * rlc_final_table + (1 - sel) * ONE
        let final_expr = final_v.iter().map(|v| v.expr()).collect_vec();
        let raw_final_table = [
            // a v t
            vec![(DVRAM::RAM_TYPE as usize).into()],
            vec![addr_subset.expr()],
            final_expr,
            vec![final_cycle.expr()],
        ]
        .concat();
        let final_table_expr = sel.expr() * cb.rlc_chip_record(raw_final_table.clone())
            + (Expression::Constant(Either::Left(E::BaseField::ONE)) - sel.expr());
        cb.r_table_rlc_record(
            || "final_table",
            DVRAM::RAM_TYPE,
            SetTableSpec {
                len: None,
                structural_witins: vec![sel],
            },
            raw_final_table,
            final_table_expr,
        )?;

        Ok(Self {
            addr_subset,
            sel,
            final_v,
            final_cycle,
            phantom: PhantomData,
            params: params.clone(),
        })
    }

    /// TODO consider taking RowMajorMatrix as argument to save allocations.
    pub fn assign_instances<F: SmallField>(
        &self,
        num_witin: usize,
        num_structural_witin: usize,
        final_mem: &[MemFinalRecord],
    ) -> Result<[RowMajorMatrix<F>; 2], CircuitBuilderError> {
        assert_eq!(num_structural_witin, 1);
        assert!(final_mem.len() <= DVRAM::max_len(&self.params));
        assert!(DVRAM::max_len(&self.params).is_power_of_two());

        let mut witness =
            RowMajorMatrix::<F>::new(final_mem.len(), num_witin, InstancePaddingStrategy::Default);
        let mut structural_witness = RowMajorMatrix::<F>::new(
            final_mem.len(),
            num_structural_witin,
            InstancePaddingStrategy::Default,
        );

        witness
            .par_rows_mut()
            .zip(structural_witness.par_rows_mut())
            .zip(final_mem)
            .enumerate()
            .for_each(|(i, ((row, structural_row), rec))| {
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

                set_val!(row, self.addr_subset, rec.addr as u64);
                set_val!(row, self.sel, 1u64);
            });

        Ok([witness, structural_witness])
    }
}

/// volatile with all init value as 0
/// dynamic address as witin, relied on augment of knowledge to prove address form
#[derive(Clone, Debug)]
pub struct DynVolatileRAMBusConfig<DVRAM: DynVolatileRamTable + Send + Sync + Clone> {
    addr_subset: WitIn,

    sel_read: StructuralWitIn,
    sel_write: StructuralWitIn,
    local_write_v: Vec<WitIn>,
    local_read_v: Vec<WitIn>,
    local_read_cycle: WitIn,

    phantom: PhantomData<DVRAM>,
    params: ProgramParams,
}

impl<DVRAM: DynVolatileRamTable + Send + Sync + Clone> DynVolatileRAMBusConfig<DVRAM> {
    pub fn construct_circuit<E: ExtensionField>(
        cb: &mut CircuitBuilder<E>,
        params: &ProgramParams,
    ) -> Result<Self, CircuitBuilderError> {
        let one = Expression::Constant(Either::Left(E::BaseField::ONE));
        let mem_bus_with_read = cb.query_mem_bus_with_read()?;
        let mem_bus_with_write = cb.query_mem_bus_with_write()?;
        let addr_subset = cb.create_witin(|| "addr_subset");
        // TODO add new selector to support sel_rw
        let sel_read = cb.create_structural_witin(
            || "sel_read",
            StructuralWitInType::EqualDistanceSequence {
                max_len: 0,
                offset: DVRAM::offset_addr(params),
                multi_factor: WORD_SIZE,
                descending: DVRAM::DESCENDING,
            },
        );
        let sel_write = cb.create_structural_witin(
            || "sel_write",
            StructuralWitInType::EqualDistanceSequence {
                max_len: 0,
                offset: DVRAM::offset_addr(params),
                multi_factor: WORD_SIZE,
                descending: DVRAM::DESCENDING,
            },
        );

        // local write
        let local_write_v = (0..DVRAM::V_LIMBS)
            .map(|i| cb.create_witin(|| format!("local_write_v_limb_{i}")))
            .collect::<Vec<WitIn>>();
        let local_write_v_expr = local_write_v.iter().map(|v| v.expr()).collect_vec();

        // local read
        let local_read_v = (0..DVRAM::V_LIMBS)
            .map(|i| cb.create_witin(|| format!("local_read_v_limb_{i}")))
            .collect::<Vec<WitIn>>();
        let local_read_v_expr: Vec<Expression<E>> =
            local_read_v.iter().map(|v| v.expr()).collect_vec();
        let local_read_cycle = cb.create_witin(|| "local_read_cycle");

        // TODO global write
        // TODO global read

        // constraints
        // read from global, write to local
        // W_{local} = mem_bus_with_read * (sel_read * local_write_record + (1 - sel_read) * ONE) + (1 - mem_bus_with_read) * ONE
        let local_raw_write_record = [
            vec![(DVRAM::RAM_TYPE as usize).into()],
            vec![addr_subset.expr()],
            local_write_v_expr.clone(),
            vec![Expression::ZERO], // mem bus local init cycle always 0.
        ]
        .concat();
        let local_write_record = cb.rlc_chip_record(local_raw_write_record.clone());
        let local_write = mem_bus_with_read.expr()
            * (sel_read.expr() * local_write_record + (one.clone() - sel_read.expr()).expr())
            + (one.clone() - mem_bus_with_read.expr());
        cb.w_table_rlc_record(
            || "local_write_record",
            DVRAM::RAM_TYPE,
            SetTableSpec {
                len: None,
                structural_witins: vec![sel_read],
            },
            local_raw_write_record,
            local_write,
        )?;
        // TODO R_{global} = mem_bus_with_read * (sel_read * global_read + (1-sel_read) * EC_INFINITY) + (1 - mem_bus_with_read) * EC_INFINITY

        // write to global, read from local
        // R_{local} = mem_bus_with_write * (sel_write * local_read_record + (1 - sel_write) * ONE) + (1 - mem_bus_with_write) * ONE
        let local_raw_read_record = [
            vec![(DVRAM::RAM_TYPE as usize).into()],
            vec![addr_subset.expr()],
            local_read_v_expr.clone(),
            vec![local_read_cycle.expr()],
        ]
        .concat();
        let local_read_record = cb.rlc_chip_record(local_raw_read_record.clone());
        let local_read: Expression<E> = mem_bus_with_write.expr()
            * (sel_write.expr() * local_read_record + (one.clone() - sel_write.expr()))
            + (one.clone() - mem_bus_with_write.expr());
        cb.r_table_rlc_record(
            || "local_read_record",
            DVRAM::RAM_TYPE,
            SetTableSpec {
                len: None,
                structural_witins: vec![sel_write],
            },
            local_raw_read_record,
            local_read,
        )?;
        // TODO W_{local} = mem_bus_with_write * (sel_write * global_write + (1 - sel_write) * EC_INFINITY) + (1 - mem_bus_with_write) * EC_INFINITY

        Ok(Self {
            addr_subset,
            sel_write,
            sel_read,
            local_write_v,
            local_read_v,
            local_read_cycle,
            phantom: PhantomData,
            params: params.clone(),
        })
    }

    /// TODO consider taking RowMajorMatrix as argument to save allocations.
    pub fn assign_instances<F: SmallField>(
        &self,
        num_witin: usize,
        num_structural_witin: usize,
        global_read_mem: &[RAMRecord],
        global_write_mem: &[RAMRecord],
    ) -> Result<[RowMajorMatrix<F>; 2], CircuitBuilderError> {
        assert!(global_read_mem.len() <= DVRAM::max_len(&self.params));
        assert!(DVRAM::max_len(&self.params).is_power_of_two());
        let witness_length = {
            let max_len = global_read_mem.len().max(global_write_mem.len());
            // first half write, second half read
            next_pow2_instance_padding(max_len) * 2
        };

        let mut witness =
            RowMajorMatrix::<F>::new(witness_length, num_witin, InstancePaddingStrategy::Default);
        let witness_mid = witness.values.len() / 2;
        let mut structural_witness = RowMajorMatrix::<F>::new(
            witness_length,
            num_structural_witin,
            InstancePaddingStrategy::Default,
        );
        let (witness_write, witness_read) = witness.values.split_at_mut(witness_mid);
        let structural_witness_mid = structural_witness.values.len() / 2;
        let (structural_witness_write, structural_witness_read) = structural_witness
            .values
            .split_at_mut(structural_witness_mid);

        rayon::join(
            // global write, local read
            || {
                witness_write
                    .par_chunks_mut(num_witin)
                    .zip(structural_witness_write.par_chunks_mut(num_structural_witin))
                    .zip(global_write_mem)
                    .enumerate()
                    .for_each(|(i, ((row, structural_row), rec))| {
                        if self.local_read_v.len() == 1 {
                            // Assign value directly.
                            set_val!(row, self.local_read_v[0], rec.value as u64);
                        } else {
                            // Assign value limbs.
                            self.local_read_v.iter().enumerate().for_each(|(l, limb)| {
                                let val = (rec.value >> (l * LIMB_BITS)) & LIMB_MASK;
                                set_val!(row, limb, val as u64);
                            });
                        }
                        set_val!(row, self.local_read_cycle, rec.cycle);

                        set_val!(row, self.addr_subset, rec.addr.baddr().0 as u64);
                        set_val!(structural_row, self.sel_write, 1u64);

                        // TODO assign W_{global}
                    });
            },
            // global read, local write
            || {
                witness_read
                    .par_chunks_mut(num_witin)
                    .zip(structural_witness_read.par_chunks_mut(num_structural_witin))
                    .zip(global_read_mem)
                    .enumerate()
                    .for_each(|(i, ((row, structural_row), rec))| {
                        if self.local_write_v.len() == 1 {
                            // Assign value directly.
                            set_val!(row, self.local_write_v[0], rec.value as u64);
                        } else {
                            // Assign value limbs.
                            self.local_write_v.iter().enumerate().for_each(|(l, limb)| {
                                let val = (rec.value >> (l * LIMB_BITS)) & LIMB_MASK;
                                set_val!(row, limb, val as u64);
                            });
                        }
                        set_val!(row, self.addr_subset, rec.addr.baddr().0 as u64);
                        set_val!(structural_row, self.sel_read, 1u64);

                        // TODO assign R_{global}
                    });
            },
        );

        structural_witness.padding_by_strategy();
        Ok([witness, structural_witness])
    }
}

#[cfg(test)]
mod tests {
    use std::iter::successors;

    use crate::{
        circuit_builder::{CircuitBuilder, ConstraintSystem},
        structs::ProgramParams,
        tables::{DynVolatileRamTable, HintsCircuit, HintsTable, MemFinalRecord, TableCircuit},
        witness::LkMultiplicity,
    };

    use ceno_emul::WORD_SIZE;
    use ff_ext::GoldilocksExt2 as E;
    use itertools::Itertools;
    use multilinear_extensions::mle::MultilinearExtension;
    use p3::{field::FieldAlgebra, goldilocks::Goldilocks as F};
    use witness::next_pow2_instance_padding;

    #[test]
    fn test_well_formed_address_padding() {
        let mut cs = ConstraintSystem::<E>::new(|| "riscv");
        let mut cb = CircuitBuilder::new(&mut cs);
        let config = HintsCircuit::construct_circuit(&mut cb, &ProgramParams::default()).unwrap();

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
        let [_, mut structural_witness] = HintsCircuit::<E>::assign_instances(
            &config,
            cb.cs.num_witin as usize,
            cb.cs.num_structural_witin as usize,
            &lkm.0,
            &input,
        )
        .unwrap();

        let addr_column = cb
            .cs
            .structural_witin_namespace_map
            .iter()
            .position(|name| name == "riscv/RAM_Memory_HintsTable/addr")
            .unwrap();

        structural_witness.padding_by_strategy();
        let addr_padded_view: MultilinearExtension<E> =
            structural_witness.to_mles()[addr_column].clone();
        // Expect addresses to proceed consecutively inside the padding as well
        let expected = successors(Some(addr_padded_view.get_base_field_vec()[0]), |idx| {
            Some(*idx + F::from_canonical_u64(WORD_SIZE as u64))
        })
        .take(next_pow2_instance_padding(
            structural_witness.num_instances(),
        ))
        .collect::<Vec<_>>();

        assert_eq!(addr_padded_view.get_base_field_vec(), expected)
    }
}
