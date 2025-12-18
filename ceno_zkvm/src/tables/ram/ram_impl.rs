use ceno_emul::Addr;
use ff_ext::{ExtensionField, SmallField};
use gkr_iop::error::CircuitBuilderError;
use itertools::Itertools;
use rayon::iter::{
    IndexedParallelIterator, IntoParallelIterator, IntoParallelRefIterator,
    IntoParallelRefMutIterator, ParallelExtend, ParallelIterator,
};
use std::marker::PhantomData;
use witness::{InstancePaddingStrategy, RowMajorMatrix, set_fixed_val, set_val};

use super::{
    MemInitRecord,
    ram_circuit::{DynVolatileRamTable, MemFinalRecord, NonVolatileTable},
};
use crate::{
    chip_handler::general::PublicIOQuery,
    circuit_builder::{CircuitBuilder, SetTableSpec},
    e2e::ShardContext,
    instructions::riscv::constants::{LIMB_BITS, LIMB_MASK},
    scheme::PublicValues,
    structs::ProgramParams,
    tables::ram::ram_circuit::DynVolatileRamTableConfigTrait,
};
use ff_ext::FieldInto;
use multilinear_extensions::{Expression, Fixed, StructuralWitIn, ToExpr, WitIn};

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
        config: &Self::Config,
        _num_witin: usize,
        num_structural_witin: usize,
        final_mem: &[MemFinalRecord],
    ) -> Result<[RowMajorMatrix<F>; 2], CircuitBuilderError> {
        if final_mem.is_empty() {
            return Ok([RowMajorMatrix::empty(), RowMajorMatrix::empty()]);
        }
        assert!(num_structural_witin == 0 || num_structural_witin == 1);
        let mut value = Vec::with_capacity(NVRAM::len(&config.params));
        value.par_extend(
            (0..NVRAM::len(&config.params))
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
        final_mem: &[MemFinalRecord],
    ) -> Result<[RowMajorMatrix<F>; 2], CircuitBuilderError> {
        if final_mem.is_empty() {
            return Ok([RowMajorMatrix::empty(), RowMajorMatrix::empty()]);
        }
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
pub struct DynVolatileRamTableInitConfig<DVRAM: DynVolatileRamTable + Send + Sync + Clone> {
    addr: StructuralWitIn,

    init_v: Option<Vec<WitIn>>,

    phantom: PhantomData<DVRAM>,
    params: ProgramParams,
}

impl<DVRAM: DynVolatileRamTable + Send + Sync + Clone> DynVolatileRamTableInitConfig<DVRAM> {
    fn assign_instances<F: SmallField>(
        config: &Self,
        num_witin: usize,
        num_structural_witin: usize,
        (final_mem, _pv, _num_instances): &(&[MemFinalRecord], &PublicValues, usize),
    ) -> Result<[RowMajorMatrix<F>; 2], CircuitBuilderError> {
        if final_mem.is_empty() {
            return Ok([RowMajorMatrix::empty(), RowMajorMatrix::empty()]);
        }
        assert_eq!(num_structural_witin, 2);

        let num_instances = final_mem.len();
        assert!(num_instances <= DVRAM::max_len(&config.params));
        assert!(DVRAM::max_len(&config.params).is_power_of_two());

        // got some duplicated code segment to simplify parallel assignment flow
        if let Some(init_v) = config.init_v.as_ref() {
            let mut witness = RowMajorMatrix::<F>::new(
                num_instances,
                num_witin,
                InstancePaddingStrategy::Default,
            );
            let mut structural_witness = RowMajorMatrix::<F>::new(
                num_instances,
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
                        if init_v.len() == 1 {
                            // Assign value directly.
                            set_val!(row, init_v[0], rec.init_value as u64);
                        } else {
                            // Assign value limbs.
                            init_v.iter().enumerate().for_each(|(l, limb)| {
                                let val = (rec.init_value >> (l * LIMB_BITS)) & LIMB_MASK;
                                set_val!(row, limb, val as u64);
                            });
                        }
                    }
                    set_val!(
                        structural_row,
                        config.addr,
                        DVRAM::addr(&config.params, i) as u64
                    );
                    if i < num_instances {
                        *structural_row.last_mut().unwrap() = F::ONE;
                    }
                });

            Ok([witness, structural_witness])
        } else {
            let mut structural_witness = RowMajorMatrix::<F>::new(
                num_instances,
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
                    if i < num_instances {
                        *structural_row.last_mut().unwrap() = F::ONE;
                    }
                });
            Ok([RowMajorMatrix::empty(), structural_witness])
        }
    }

    fn assign_instances_dynamic<F: SmallField>(
        config: &Self,
        _num_witin: usize,
        num_structural_witin: usize,
        (_final_mem, pv, num_instances): &(&[MemFinalRecord], &PublicValues, usize),
    ) -> Result<[RowMajorMatrix<F>; 2], CircuitBuilderError> {
        assert!(
            DVRAM::ZERO_INIT,
            "do not support dynamic address with non-zero init"
        );
        let mut structural_witness = RowMajorMatrix::<F>::new(
            *num_instances,
            num_structural_witin,
            InstancePaddingStrategy::Default,
        );
        structural_witness
            .par_rows_mut()
            .enumerate()
            .for_each(|(i, structural_row)| {
                set_val!(
                    structural_row,
                    config.addr,
                    DVRAM::dynamic_addr(&config.params, i, pv) as u64
                );
                *structural_row.last_mut().unwrap() = F::ONE;
            });
        Ok([RowMajorMatrix::empty(), structural_witness])
    }
}

impl<DVRAM: DynVolatileRamTable + Send + Sync + Clone> DynVolatileRamTableConfigTrait<DVRAM>
    for DynVolatileRamTableInitConfig<DVRAM>
{
    type Config = DynVolatileRamTableInitConfig<DVRAM>;
    type WitnessInput<'a> = (&'a [MemFinalRecord], &'a PublicValues, usize);

    fn construct_circuit<E: ExtensionField>(
        cb: &mut CircuitBuilder<E>,
        params: &ProgramParams,
    ) -> Result<Self, CircuitBuilderError> {
        cb.set_omc_init_only();

        let (addr_expr, addr) = DVRAM::addr_expr(cb, params)?;

        let (init_expr, init_v) = if DVRAM::ZERO_INIT {
            (vec![Expression::ZERO; DVRAM::V_LIMBS], None)
        } else {
            let init_v = (0..DVRAM::V_LIMBS)
                .map(|i| cb.create_witin(|| format!("init_v_limb_{i}")))
                .collect::<Vec<WitIn>>();
            (init_v.iter().map(|v| v.expr()).collect_vec(), Some(init_v))
        };

        let init_table = [
            vec![(DVRAM::RAM_TYPE as usize).into()],
            vec![addr_expr.expr()],
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
            init_v,
            phantom: PhantomData,
            params: params.clone(),
        })
    }

    /// TODO consider taking RowMajorMatrix as argument to save allocations.
    fn assign_instances<'a, F: SmallField>(
        config: &Self::Config,
        num_witin: usize,
        num_structural_witin: usize,
        data: &(&[MemFinalRecord], &PublicValues, usize),
    ) -> Result<[RowMajorMatrix<F>; 2], CircuitBuilderError> {
        let (final_mem, _, _) = &data;
        if final_mem.is_empty() {
            return Ok([RowMajorMatrix::empty(), RowMajorMatrix::empty()]);
        }
        assert_eq!(num_structural_witin, 2);
        if DVRAM::DYNAMIC_OFFSET {
            Self::assign_instances_dynamic(config, num_witin, num_structural_witin, data)
        } else {
            Self::assign_instances(config, num_witin, num_structural_witin, data)
        }
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
        final_mem: &[(&'static str, &[MemFinalRecord])],
    ) -> Result<[RowMajorMatrix<F>; 2], CircuitBuilderError> {
        assert!(num_structural_witin == 0 || num_structural_witin == 1);
        let num_structural_witin = num_structural_witin.max(1);

        let is_current_shard_mem_record = |record: &&MemFinalRecord| -> bool {
            (shard_ctx.is_first_shard() && record.cycle == 0)
                || shard_ctx.is_in_current_shard(record.cycle)
        };

        // collect each raw mem belong to this shard, BEFORE padding length
        let mem_lens: Vec<usize> = final_mem
            .par_iter()
            .map(|(_, mem)| mem.par_iter().filter(is_current_shard_mem_record).count())
            .collect();

        // calculate mem length
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

        let current_shard_offset_cycle = shard_ctx.current_shard_offset_cycle();

        witness_mut_slices
            .par_iter_mut()
            .zip_eq(structural_witness_mut_slices.par_iter_mut())
            .zip_eq(final_mem.par_iter())
            .for_each(|((witness, structural_witness), (_, final_mem))| {
                witness
                    .chunks_mut(num_witin)
                    .zip_eq(structural_witness.chunks_mut(num_structural_witin))
                    .zip(final_mem.iter().filter(is_current_shard_mem_record))
                    .for_each(|((row, structural_row), rec)| {
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
                        let shard_cycle = rec.cycle - current_shard_offset_cycle;
                        set_val!(row, self.final_cycle, shard_cycle);

                        set_val!(row, self.ram_type, rec.ram_type as u64);
                        set_val!(row, self.addr_subset, rec.addr as u64);
                        *structural_row.last_mut().unwrap() = F::ONE;
                    });
            });

        Ok([witness, structural_witness])
    }
}

#[cfg(test)]
mod tests {
    use std::iter::successors;

    use crate::{
        circuit_builder::{CircuitBuilder, ConstraintSystem},
        structs::ProgramParams,
        tables::{DynVolatileRamTable, HintsInitCircuit, HintsTable, MemFinalRecord, TableCircuit},
        witness::LkMultiplicity,
    };

    use crate::scheme::PublicValues;
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
            HintsInitCircuit::build_gkr_iop_circuit(&mut cb, &ProgramParams::default()).unwrap();

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
        let [_, mut structural_witness] = HintsInitCircuit::<E>::assign_instances(
            &config,
            cb.cs.num_witin as usize,
            cb.cs.num_structural_witin as usize,
            &lkm.0,
            &(&input, &PublicValues::default(), 0),
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
