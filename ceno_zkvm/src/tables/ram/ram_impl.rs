use ceno_emul::{Addr, WORD_SIZE};
use either::Either;
use ff_ext::{ExtensionField, SmallField};
use gkr_iop::error::CircuitBuilderError;
use itertools::Itertools;
use rayon::iter::{
    IndexedParallelIterator, IntoParallelIterator, IntoParallelRefIterator,
    IntoParallelRefMutIterator, ParallelExtend, ParallelIterator,
};
use std::marker::PhantomData;
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
    e2e::ShardContext,
    instructions::riscv::constants::{LIMB_BITS, LIMB_MASK},
    structs::{ProgramParams, WitnessId},
    tables::ram::ram_circuit::DynVolatileRamTableConfigTrait,
};
use ff_ext::FieldInto;
use gkr_iop::RAMType;
use multilinear_extensions::{
    Expression, Fixed, StructuralWitIn, StructuralWitInType, ToExpr, WitIn,
};
use p3::field::FieldAlgebra;

pub trait NonVolatileTableConfigTrait<NVRAM>: Sized + Send + Sync {
    type Config: Sized + Send + Sync;

    fn construct_circuit<E: ExtensionField>(
        cb: &mut CircuitBuilder<E>,
        params: &ProgramParams,
    ) -> Result<Self::Config, CircuitBuilderError>;

    fn gen_init_state<F: SmallField>(
        config: &Self::Config,
        num_fixed: usize,
        init_mem: &[MemInitRecord],
    ) -> RowMajorMatrix<F>;

    fn assign_instances<F: SmallField>(
        config: &Self::Config,
        num_witin: usize,
        num_structural_witin: usize,
        final_mem: &[MemFinalRecord],
    ) -> Result<[RowMajorMatrix<F>; 2], CircuitBuilderError>;
}

/// define a non-volatile memory with init value
#[derive(Clone, Debug)]
pub struct NonVolatileInitTableConfig<NVRAM: NonVolatileTable + Send + Sync + Clone> {
    init_v: Vec<Fixed>,
    addr: Fixed,

    phantom: PhantomData<NVRAM>,
    params: ProgramParams,
}

impl<NVRAM: NonVolatileTable + Send + Sync + Clone> NonVolatileTableConfigTrait<NVRAM>
    for NonVolatileInitTableConfig<NVRAM>
{
    type Config = NonVolatileInitTableConfig<NVRAM>;

    fn construct_circuit<E: ExtensionField>(
        cb: &mut CircuitBuilder<E>,
        params: &ProgramParams,
    ) -> Result<Self, CircuitBuilderError> {
        cb.set_omc_init_only();
        assert!(NVRAM::WRITABLE);
        let init_v = (0..NVRAM::V_LIMBS)
            .map(|i| cb.create_fixed(|| format!("init_v_limb_{i}")))
            .collect_vec();
        let addr = cb.create_fixed(|| "addr");

        let init_table = [
            vec![(NVRAM::RAM_TYPE as usize).into()],
            vec![Expression::Fixed(addr)],
            init_v.iter().map(|v| v.expr()).collect_vec(),
            vec![Expression::ZERO], // Initial cycle.
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

        Ok(Self {
            init_v,
            addr,
            phantom: PhantomData,
            params: params.clone(),
        })
    }

    fn gen_init_state<F: SmallField>(
        config: &Self::Config,
        num_fixed: usize,
        init_mem: &[MemInitRecord],
    ) -> RowMajorMatrix<F> {
        assert!(
            NVRAM::len(&config.params).is_power_of_two(),
            "{} len {} must be a power of 2",
            NVRAM::name(),
            NVRAM::len(&config.params)
        );

        let mut init_table = RowMajorMatrix::<F>::new(
            NVRAM::len(&config.params),
            num_fixed,
            InstancePaddingStrategy::Default,
        );
        assert_eq!(init_table.num_padding_instances(), 0);

        init_table
            .par_rows_mut()
            .zip_eq(init_mem)
            .for_each(|(row, rec)| {
                if config.init_v.len() == 1 {
                    // Assign value directly.
                    set_fixed_val!(row, config.init_v[0], (rec.value as u64).into_f());
                } else {
                    // Assign value limbs.
                    config.init_v.iter().enumerate().for_each(|(l, limb)| {
                        let val = (rec.value >> (l * LIMB_BITS)) & LIMB_MASK;
                        set_fixed_val!(row, limb, (val as u64).into_f());
                    });
                }
                set_fixed_val!(row, config.addr, (rec.addr as u64).into_f());
            });

        init_table
    }

    /// TODO consider taking RowMajorMatrix as argument to save allocations.
    fn assign_instances<F: SmallField>(
        _config: &Self::Config,
        _num_witin: usize,
        num_structural_witin: usize,
        _final_mem: &[MemFinalRecord],
    ) -> Result<[RowMajorMatrix<F>; 2], CircuitBuilderError> {
        assert!(num_structural_witin == 0 || num_structural_witin == 1);
        let mut value = Vec::with_capacity(NVRAM::len(&_config.params));
        value.par_extend(
            (0..NVRAM::len(&_config.params))
                .into_par_iter()
                .map(|_| F::ONE),
        );
        let structural_witness =
            RowMajorMatrix::<F>::new_by_values(value, 1, InstancePaddingStrategy::Default);
        Ok([RowMajorMatrix::empty(), structural_witness])
    }
}

/// define public io
/// init value set by instance
#[derive(Clone, Debug)]
pub struct PubIOTableInitConfig<NVRAM: NonVolatileTable + Send + Sync + Clone> {
    addr: Fixed,
    phantom: PhantomData<NVRAM>,
    params: ProgramParams,
}

impl<NVRAM: NonVolatileTable + Send + Sync + Clone> PubIOTableInitConfig<NVRAM> {
    pub fn construct_circuit<E: ExtensionField>(
        cb: &mut CircuitBuilder<E>,
        params: &ProgramParams,
    ) -> Result<Self, CircuitBuilderError> {
        assert!(!NVRAM::WRITABLE);
        let init_v = cb.query_public_io()?;
        let addr = cb.create_fixed(|| "addr");

        let init_table = [
            vec![(NVRAM::RAM_TYPE as usize).into()],
            vec![Expression::Fixed(addr)],
            init_v.iter().map(|v| v.expr_as_instance()).collect_vec(),
            vec![Expression::ZERO], // Initial cycle.
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

        Ok(Self {
            addr,
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
        _num_witin: usize,
        num_structural_witin: usize,
        _final_mem: &[MemFinalRecord],
    ) -> Result<[RowMajorMatrix<F>; 2], CircuitBuilderError> {
        assert!(num_structural_witin == 0 || num_structural_witin == 1);
        let mut value = Vec::with_capacity(NVRAM::len(&self.params));
        value.par_extend(
            (0..NVRAM::len(&self.params))
                .into_par_iter()
                .map(|_| F::ONE),
        );
        let structural_witness =
            RowMajorMatrix::<F>::new_by_values(value, 1, InstancePaddingStrategy::Default);
        Ok([RowMajorMatrix::empty(), structural_witness])
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

impl<DVRAM: DynVolatileRamTable + Send + Sync + Clone> DynVolatileRamTableConfigTrait<DVRAM>
    for DynVolatileRamTableConfig<DVRAM>
{
    type Config = DynVolatileRamTableConfig<DVRAM>;
    fn construct_circuit<E: ExtensionField>(
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
    fn assign_instances<F: SmallField>(
        config: &Self::Config,
        num_witin: usize,
        num_structural_witin: usize,
        final_mem: &[MemFinalRecord],
    ) -> Result<[RowMajorMatrix<F>; 2], CircuitBuilderError> {
        if final_mem.is_empty() {
            return Ok([RowMajorMatrix::empty(), RowMajorMatrix::empty()]);
        }
        assert_eq!(num_structural_witin, 2);

        let num_instances_padded = next_pow2_instance_padding(final_mem.len());
        assert!(num_instances_padded <= DVRAM::max_len(&config.params));
        assert!(DVRAM::max_len(&config.params).is_power_of_two());
        let selector_witin = WitIn {
            id: num_structural_witin as WitnessId - 1,
        };

        let mut witness = RowMajorMatrix::<F>::new(
            num_instances_padded,
            num_witin,
            InstancePaddingStrategy::Default,
        );
        let mut structural_witness = RowMajorMatrix::<F>::new(
            num_instances_padded,
            num_structural_witin,
            InstancePaddingStrategy::Default,
        );

        witness
            .par_rows_mut()
            .zip_eq(structural_witness.par_rows_mut())
            .enumerate()
            .for_each(|(i, (row, structural_row))| {
                if cfg!(debug_assertions)
                    && let Some(addr) = final_mem.get(i).map(|rec| rec.addr)
                {
                    debug_assert_eq!(
                        addr,
                        DVRAM::addr(&config.params, i),
                        "rec.addr {:x} != expected {:x}",
                        addr,
                        DVRAM::addr(&config.params, i),
                    );
                }

                if let Some(rec) = final_mem.get(i) {
                    if config.final_v.len() == 1 {
                        // Assign value directly.
                        set_val!(row, config.final_v[0], rec.value as u64);
                    } else {
                        // Assign value limbs.
                        config.final_v.iter().enumerate().for_each(|(l, limb)| {
                            let val = (rec.value >> (l * LIMB_BITS)) & LIMB_MASK;
                            set_val!(row, limb, val as u64);
                        });
                    }
                    set_val!(row, config.final_cycle, rec.cycle);
                }
                set_val!(
                    structural_row,
                    config.addr,
                    DVRAM::addr(&config.params, i) as u64
                );
                set_val!(structural_row, selector_witin, 1u64);
            });

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

impl<DVRAM: DynVolatileRamTable + Send + Sync + Clone> DynVolatileRamTableConfigTrait<DVRAM>
    for DynVolatileRamTableInitConfig<DVRAM>
{
    type Config = DynVolatileRamTableInitConfig<DVRAM>;

    fn construct_circuit<E: ExtensionField>(
        cb: &mut CircuitBuilder<E>,
        params: &ProgramParams,
    ) -> Result<Self, CircuitBuilderError> {
        cb.set_omc_init_only();
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
    fn assign_instances<F: SmallField>(
        config: &Self::Config,
        _num_witin: usize,
        num_structural_witin: usize,
        final_mem: &[MemFinalRecord],
    ) -> Result<[RowMajorMatrix<F>; 2], CircuitBuilderError> {
        if final_mem.is_empty() {
            return Ok([RowMajorMatrix::empty(), RowMajorMatrix::empty()]);
        }
        assert_eq!(num_structural_witin, 2);

        let num_instances_padded = next_pow2_instance_padding(final_mem.len());
        assert!(num_instances_padded <= DVRAM::max_len(&config.params));
        assert!(DVRAM::max_len(&config.params).is_power_of_two());
        let selector_witin = WitIn {
            id: num_structural_witin as WitnessId - 1,
        };

        let mut structural_witness = RowMajorMatrix::<F>::new(
            num_instances_padded,
            num_structural_witin,
            InstancePaddingStrategy::Default,
        );

        structural_witness
            .par_rows_mut()
            .enumerate()
            .for_each(|(i, structural_row)| {
                if cfg!(debug_assertions)
                    && let Some(addr) = final_mem.get(i).map(|rec| rec.addr)
                {
                    debug_assert_eq!(
                        addr,
                        DVRAM::addr(&config.params, i),
                        "rec.addr {:x} != expected {:x}",
                        addr,
                        DVRAM::addr(&config.params, i),
                    );
                }
                set_val!(
                    structural_row,
                    config.addr,
                    DVRAM::addr(&config.params, i) as u64
                );
                set_val!(structural_row, selector_witin, 1u64);
            });

        Ok([RowMajorMatrix::empty(), structural_witness])
    }
}

/// This table is generalized version to handle all mmio records
#[derive(Clone, Debug)]
pub struct LocalFinalRAMTableConfig<const V_LIMBS: usize> {
    addr_subset: WitIn,
    ram_type: WitIn,

    final_v: Vec<WitIn>,
    final_cycle: WitIn,
}

impl<const V_LIMBS: usize> LocalFinalRAMTableConfig<V_LIMBS> {
    pub fn construct_circuit<E: ExtensionField>(
        cb: &mut CircuitBuilder<E>,
        _params: &ProgramParams,
    ) -> Result<Self, CircuitBuilderError> {
        let addr_subset = cb.create_witin(|| "addr_subset");
        let ram_type = cb.create_witin(|| "ram_type");

        let final_v = (0..V_LIMBS)
            .map(|i| cb.create_witin(|| format!("final_v_limb_{i}")))
            .collect::<Vec<WitIn>>();
        let final_cycle = cb.create_witin(|| "final_cycle");

        let final_expr = final_v.iter().map(|v| v.expr()).collect_vec();
        let raw_final_table = [
            // a v t
            vec![ram_type.expr()],
            vec![addr_subset.expr()],
            final_expr,
            vec![final_cycle.expr()],
        ]
        .concat();
        let rlc_record = cb.rlc_chip_record(raw_final_table.clone());
        cb.r_table_rlc_record(
            || "final_table",
            // XXX we mixed all ram type here to save column allocation
            ram_type.expr(),
            SetTableSpec {
                len: None,
                structural_witins: vec![],
            },
            raw_final_table,
            rlc_record,
        )?;

        Ok(Self {
            addr_subset,
            ram_type,
            final_v,
            final_cycle,
        })
    }

    /// TODO consider taking RowMajorMatrix as argument to save allocations.
    pub fn assign_instances<F: SmallField>(
        &self,
        shard_ctx: &ShardContext,
        num_witin: usize,
        num_structural_witin: usize,
        final_mem: &[(InstancePaddingStrategy, &[MemFinalRecord])],
    ) -> Result<[RowMajorMatrix<F>; 2], CircuitBuilderError> {
        assert!(num_structural_witin == 0 || num_structural_witin == 1);
        let num_structural_witin = num_structural_witin.max(1);
        let selector_witin = WitIn { id: 0 };

        let is_current_shard_mem_record = |record: &&MemFinalRecord| -> bool {
            (shard_ctx.is_first_shard() && record.cycle == 0)
                || shard_ctx.is_current_shard_cycle(record.cycle)
        };

        // collect each raw mem belong to this shard, BEFORE padding length
        let current_shard_mems_len: Vec<usize> = final_mem
            .par_iter()
            .map(|(_, mem)| mem.par_iter().filter(is_current_shard_mem_record).count())
            .collect();

        // deal with non-pow2 padding for first shard
        // format Vec<(pad_len, pad_start_index)>
        let padding_info = if shard_ctx.is_first_shard() {
            final_mem
                .iter()
                .map(|(_, mem)| {
                    assert!(!mem.is_empty());
                    (
                        next_pow2_instance_padding(mem.len()) - mem.len(),
                        mem.len(),
                        mem[0].ram_type,
                    )
                })
                .collect_vec()
        } else {
            vec![(0, 0, RAMType::Undefined); final_mem.len()]
        };

        // calculate mem length
        let mem_lens = current_shard_mems_len
            .iter()
            .zip_eq(&padding_info)
            .map(|(raw_len, (pad_len, _, _))| raw_len + pad_len)
            .collect_vec();
        let total_records = mem_lens.iter().sum();

        let mut witness =
            RowMajorMatrix::<F>::new(total_records, num_witin, InstancePaddingStrategy::Default);
        let mut structural_witness = RowMajorMatrix::<F>::new(
            total_records,
            num_structural_witin,
            InstancePaddingStrategy::Default,
        );

        let mut witness_mut_slices = Vec::with_capacity(final_mem.len());
        let mut structural_witness_mut_slices = Vec::with_capacity(final_mem.len());
        let mut witness_value_rest = witness.values.as_mut_slice();
        let mut structural_witness_value_rest = structural_witness.values.as_mut_slice();

        for mem_len in mem_lens {
            let witness_length = mem_len * num_witin;
            let structural_witness_length = mem_len * num_structural_witin;
            assert!(
                witness_length <= witness_value_rest.len(),
                "chunk size exceeds remaining data"
            );
            assert!(
                structural_witness_length <= structural_witness_value_rest.len(),
                "chunk size exceeds remaining data"
            );
            let (witness_left, witness_r) = witness_value_rest.split_at_mut(witness_length);
            let (structural_witness_left, structural_witness_r) =
                structural_witness_value_rest.split_at_mut(structural_witness_length);
            witness_mut_slices.push(witness_left);
            structural_witness_mut_slices.push(structural_witness_left);
            witness_value_rest = witness_r;
            structural_witness_value_rest = structural_witness_r;
        }

        witness_mut_slices
            .par_iter_mut()
            .zip_eq(structural_witness_mut_slices.par_iter_mut())
            .zip_eq(final_mem.par_iter())
            .zip_eq(padding_info.par_iter())
            .for_each(
                |(
                    ((witness, structural_witness), (padding_strategy, final_mem)),
                    (pad_size, pad_start_index, ram_type),
                )| {
                    let mem_record_count = witness
                        .chunks_mut(num_witin)
                        .zip_eq(structural_witness.chunks_mut(num_structural_witin))
                        .zip(final_mem.iter().filter(is_current_shard_mem_record))
                        .map(|((row, structural_row), rec)| {
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

                            set_val!(row, self.ram_type, rec.ram_type as u64);
                            set_val!(row, self.addr_subset, rec.addr as u64);
                            set_val!(structural_row, selector_witin, 1u64);
                        })
                        .count();

                    if *pad_size > 0 && shard_ctx.is_first_shard() {
                        match padding_strategy {
                            InstancePaddingStrategy::Custom(pad_func) => {
                                witness[mem_record_count * num_witin..]
                                    .chunks_mut(num_witin)
                                    .zip_eq(
                                        structural_witness
                                            [mem_record_count * num_structural_witin..]
                                            .chunks_mut(num_structural_witin),
                                    )
                                    .zip_eq(
                                        std::iter::successors(Some(*pad_start_index), |n| {
                                            Some(*n + 1)
                                        })
                                        .take(*pad_size),
                                    )
                                    .for_each(|((row, structural_row), pad_index)| {
                                        set_val!(
                                            row,
                                            self.addr_subset,
                                            pad_func(pad_index as u64, self.addr_subset.id as u64)
                                        );
                                        set_val!(row, self.ram_type, *ram_type as u64);
                                        set_val!(structural_row, selector_witin, 1u64);
                                    });
                            }
                            _ => unimplemented!(),
                        }
                    }
                },
            );

        Ok([witness, structural_witness])
    }
}

/// The general config to handle ram bus across all records
#[derive(Clone, Debug)]
pub struct RAMBusConfig<const V_LIMBS: usize> {
    addr_subset: WitIn,

    sel_read: StructuralWitIn,
    sel_write: StructuralWitIn,
    local_write_v: Vec<WitIn>,
    local_read_v: Vec<WitIn>,
    local_read_cycle: WitIn,
}

impl<const V_LIMBS: usize> RAMBusConfig<V_LIMBS> {
    pub fn construct_circuit<E: ExtensionField>(
        cb: &mut CircuitBuilder<E>,
        _params: &ProgramParams,
    ) -> Result<Self, CircuitBuilderError> {
        let ram_type = cb.create_witin(|| "ram_type");
        let one = Expression::Constant(Either::Left(E::BaseField::ONE));
        let addr_subset = cb.create_witin(|| "addr_subset");
        // TODO add new selector to support sel_rw
        let sel_read = cb.create_structural_witin(
            || "sel_read",
            StructuralWitInType::EqualDistanceSequence {
                max_len: 0,
                offset: 0,
                multi_factor: WORD_SIZE,
                descending: false,
            },
        );
        let sel_write = cb.create_structural_witin(
            || "sel_write",
            StructuralWitInType::EqualDistanceSequence {
                max_len: 0,
                offset: 0,
                multi_factor: WORD_SIZE,
                descending: false,
            },
        );

        // local write
        let local_write_v = (0..V_LIMBS)
            .map(|i| cb.create_witin(|| format!("local_write_v_limb_{i}")))
            .collect::<Vec<WitIn>>();
        let local_write_v_expr = local_write_v.iter().map(|v| v.expr()).collect_vec();

        // local read
        let local_read_v = (0..V_LIMBS)
            .map(|i| cb.create_witin(|| format!("local_read_v_limb_{i}")))
            .collect::<Vec<WitIn>>();
        let local_read_v_expr: Vec<Expression<E>> =
            local_read_v.iter().map(|v| v.expr()).collect_vec();
        let local_read_cycle = cb.create_witin(|| "local_read_cycle");

        // TODO global write
        // TODO global read

        // constraints
        // read from global, write to local
        // W_{local} = sel_read * local_write_record + (1 - sel_read) * ONE
        let local_raw_write_record = [
            vec![ram_type.expr()],
            vec![addr_subset.expr()],
            local_write_v_expr.clone(),
            vec![Expression::ZERO], // mem bus local init cycle always 0.
        ]
        .concat();
        let local_write_record = cb.rlc_chip_record(local_raw_write_record.clone());
        let local_write =
            sel_read.expr() * local_write_record + (one.clone() - sel_read.expr()).expr();
        // local write, global read
        cb.w_table_rlc_record(
            || "local_write_record",
            ram_type.expr(),
            SetTableSpec {
                len: None,
                structural_witins: vec![sel_read],
            },
            local_raw_write_record,
            local_write,
        )?;
        // TODO R_{global} = mem_bus_with_read * (sel_read * global_read + (1-sel_read) * EC_INFINITY) + (1 - mem_bus_with_read) * EC_INFINITY

        // write to global, read from local
        // R_{local} = sel_write * local_read_record + (1 - sel_write) * ONE
        let local_raw_read_record = [
            vec![ram_type.expr()],
            vec![addr_subset.expr()],
            local_read_v_expr.clone(),
            vec![local_read_cycle.expr()],
        ]
        .concat();
        let local_read_record = cb.rlc_chip_record(local_raw_read_record.clone());
        let local_read: Expression<E> =
            sel_write.expr() * local_read_record + (one.clone() - sel_write.expr());

        // local read, global write
        cb.r_table_rlc_record(
            || "local_read_record",
            ram_type.expr(),
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
        })
    }

    /// TODO consider taking RowMajorMatrix as argument to save allocations.
    pub fn assign_instances<F: SmallField>(
        &self,
        shard_ctx: &ShardContext,
        num_witin: usize,
        num_structural_witin: usize,
    ) -> Result<[RowMajorMatrix<F>; 2], CircuitBuilderError> {
        let (global_read_records, global_write_records) =
            (shard_ctx.read_records(), shard_ctx.write_records());
        assert_eq!(global_read_records.len(), global_write_records.len());
        let raw_write_len: usize = global_write_records.iter().map(|m| m.len()).sum();
        let raw_read_len: usize = global_read_records.iter().map(|m| m.len()).sum();
        if raw_read_len + raw_write_len == 0 {
            return Ok([RowMajorMatrix::empty(), RowMajorMatrix::empty()]);
        }
        // TODO refactor to deal with only read/write

        let witness_length = {
            let max_len = raw_read_len.max(raw_write_len);
            // first half write, second half read
            next_pow2_instance_padding(max_len) * 2
        };
        let mut witness =
            RowMajorMatrix::<F>::new(witness_length, num_witin, InstancePaddingStrategy::Default);
        let mut structural_witness = RowMajorMatrix::<F>::new(
            witness_length,
            num_structural_witin,
            InstancePaddingStrategy::Default,
        );
        let witness_mid = witness.values.len() / 2;
        let (witness_write, witness_read) = witness.values.split_at_mut(witness_mid);
        let structural_witness_mid = structural_witness.values.len() / 2;
        let (structural_witness_write, structural_witness_read) = structural_witness
            .values
            .split_at_mut(structural_witness_mid);

        let mut witness_write_mut_slices = Vec::with_capacity(global_write_records.len());
        let mut witness_read_mut_slices = Vec::with_capacity(global_read_records.len());
        let mut structural_witness_write_mut_slices =
            Vec::with_capacity(global_write_records.len());
        let mut structural_witness_read_mut_slices = Vec::with_capacity(global_read_records.len());
        let mut witness_write_value_rest = witness_write;
        let mut witness_read_value_rest = witness_read;
        let mut structural_witness_write_value_rest = structural_witness_write;
        let mut structural_witness_read_value_rest = structural_witness_read;

        for (global_read_record, global_write_record) in
            global_read_records.iter().zip_eq(global_write_records)
        {
            let witness_write_length = global_write_record.len() * num_witin;
            let witness_read_length = global_read_record.len() * num_witin;
            let structural_witness_write_length = global_write_record.len() * num_structural_witin;
            let structural_witness_read_length = global_read_record.len() * num_structural_witin;
            assert!(
                witness_write_length <= witness_write_value_rest.len(),
                "chunk size exceeds remaining data"
            );
            assert!(
                witness_read_length <= witness_read_value_rest.len(),
                "chunk size exceeds remaining data"
            );
            assert!(
                structural_witness_write_length <= structural_witness_write_value_rest.len(),
                "chunk size exceeds remaining data"
            );
            assert!(
                structural_witness_read_length <= structural_witness_read_value_rest.len(),
                "chunk size exceeds remaining data"
            );
            let (witness_write, witness_write_r) =
                witness_write_value_rest.split_at_mut(witness_write_length);
            witness_write_mut_slices.push(witness_write);
            witness_write_value_rest = witness_write_r;

            let (witness_read, witness_read_r) =
                witness_read_value_rest.split_at_mut(witness_read_length);
            witness_read_mut_slices.push(witness_read);
            witness_read_value_rest = witness_read_r;

            let (structural_witness_write, structural_witness_write_r) =
                structural_witness_write_value_rest.split_at_mut(structural_witness_write_length);
            structural_witness_write_mut_slices.push(structural_witness_write);
            structural_witness_write_value_rest = structural_witness_write_r;

            let (structural_witness_read, structural_witness_read_r) =
                structural_witness_read_value_rest.split_at_mut(structural_witness_read_length);
            structural_witness_read_mut_slices.push(structural_witness_read);
            structural_witness_read_value_rest = structural_witness_read_r;
        }

        rayon::join(
            // global write, local read
            || {
                witness_write_mut_slices
                    .par_iter_mut()
                    .zip_eq(structural_witness_write_mut_slices.par_iter_mut())
                    .zip_eq(global_write_records.par_iter())
                    .for_each(
                        |((witness_write, structural_witness_write), global_write_mem)| {
                            witness_write
                                .chunks_mut(num_witin)
                                .zip_eq(structural_witness_write.chunks_mut(num_structural_witin))
                                .zip_eq(global_write_mem.values())
                                .for_each(|((row, structural_row), rec)| {
                                    if self.local_read_v.len() == 1 {
                                        // Assign value directly.
                                        set_val!(row, self.local_read_v[0], rec.value as u64);
                                    } else {
                                        // Assign value limbs.
                                        self.local_read_v.iter().enumerate().for_each(
                                            |(l, limb)| {
                                                let val =
                                                    (rec.value >> (l * LIMB_BITS)) & LIMB_MASK;
                                                set_val!(row, limb, val as u64);
                                            },
                                        );
                                    }
                                    set_val!(row, self.local_read_cycle, rec.cycle);

                                    set_val!(row, self.addr_subset, rec.addr.baddr().0 as u64);
                                    set_val!(structural_row, self.sel_write, 1u64);

                                    // TODO assign W_{global}
                                });
                        },
                    );
            },
            // global read, local write
            || {
                witness_read_mut_slices
                    .par_iter_mut()
                    .zip_eq(structural_witness_read_mut_slices.par_iter_mut())
                    .zip_eq(global_read_records.par_iter())
                    .for_each(
                        |((witness_read, structural_witness_read), global_read_mem)| {
                            witness_read
                                .chunks_mut(num_witin)
                                .zip_eq(structural_witness_read.chunks_mut(num_structural_witin))
                                .zip_eq(global_read_mem.values())
                                .for_each(|((row, structural_row), rec)| {
                                    if self.local_write_v.len() == 1 {
                                        // Assign value directly.
                                        set_val!(row, self.local_write_v[0], rec.value as u64);
                                    } else {
                                        // Assign value limbs.
                                        self.local_write_v.iter().enumerate().for_each(
                                            |(l, limb)| {
                                                let val =
                                                    (rec.value >> (l * LIMB_BITS)) & LIMB_MASK;
                                                set_val!(row, limb, val as u64);
                                            },
                                        );
                                    }
                                    set_val!(row, self.addr_subset, rec.addr.baddr().0 as u64);
                                    set_val!(structural_row, self.sel_read, 1u64);

                                    // TODO assign R_{global}
                                });
                        },
                    );
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
    use gkr_iop::RAMType;
    use itertools::Itertools;
    use multilinear_extensions::mle::MultilinearExtension;
    use p3::{field::FieldAlgebra, goldilocks::Goldilocks as F};
    use witness::next_pow2_instance_padding;

    #[test]
    fn test_well_formed_address_padding() {
        let mut cs = ConstraintSystem::<E>::new(|| "riscv");
        let mut cb = CircuitBuilder::new(&mut cs);
        let (config, _) =
            HintsCircuit::build_gkr_iop_circuit(&mut cb, &ProgramParams::default()).unwrap();

        let def_params = ProgramParams::default();
        let lkm = LkMultiplicity::default().into_finalize_result();

        // ensure non-empty padding is required
        let some_non_2_pow = 26;
        let input = (0..some_non_2_pow)
            .map(|i| MemFinalRecord {
                ram_type: RAMType::Memory,
                addr: HintsTable::addr(&def_params, i),
                cycle: 0,
                value: 0,
                init_value: 0,
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
            .position(|name| name == "riscv/HintsTable_Memory_RAM/addr")
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
