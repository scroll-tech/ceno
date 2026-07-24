use std::{array, marker::PhantomData};

use ceno_emul::{
    ByteAddr, Change, Cycle, InsnKind, KECCAK_PERMUTE, Platform, StepIndex, StepRecord, WORD_SIZE,
    WriteOp,
};
use ff_ext::ExtensionField;
use gkr_iop::{
    ProtocolBuilder, ProtocolWitnessGenerator, gkr::GKRCircuit,
    utils::lk_multiplicity::Multiplicity,
};
use itertools::{Itertools, izip};
use multilinear_extensions::{ToExpr, util::max_usable_threads};
use rayon::{
    iter::{IndexedParallelIterator, ParallelIterator},
    slice::ParallelSlice,
};
use witness::{InstancePaddingStrategy, RowMajorMatrix};

use crate::{
    chip_handler::{MemoryExpr, general::InstFetch},
    circuit_builder::CircuitBuilder,
    e2e::ShardContext,
    error::ZKVMError,
    instructions::{
        Instruction,
        riscv::{
            constants::{LIMB_BITS, LIMB_MASK, MEM_BITS, UInt},
            ecall_base::OpFixedRS,
            insn_base::{MemAddr, StateInOut, WriteMEM},
        },
    },
    precompiles::{
        KECCAK_INPUT32_SIZE, KECCAK_ROUNDS, KECCAK_STATE_PHASE_INPUT, KECCAK_STATE_PHASE_OUTPUT,
        KeccakInstance, KeccakLayout, KeccakParams, KeccakStateInstance, KeccakTrace,
        KeccakWitInstance, keccak_state_record,
    },
    structs::{ProgramParams, RAMType},
    tables::{InsnRecord, RMMCollections},
    uint::Value,
    witness::LkMultiplicity,
};
use p3::field::PrimeCharacteristicRing;

#[derive(Debug)]
pub struct KeccakEcallConfig<E: ExtensionField> {
    pub(crate) vm_state: StateInOut<E>,
    pub(crate) ecall_id: OpFixedRS<E, { Platform::reg_ecall() }, false>,
    pub(crate) state_ptr: (OpFixedRS<E, { Platform::reg_arg0() }, true>, MemAddr<E>),
    pub(crate) input_state: [MemoryExpr<E>; KECCAK_INPUT32_SIZE],
    pub(crate) output_state: [MemoryExpr<E>; KECCAK_INPUT32_SIZE],
    pub(crate) mem_rw: Vec<WriteMEM>,
}

#[derive(Debug)]
pub struct KeccakCoreConfig<E: ExtensionField> {
    pub layout: KeccakLayout<E>,
}

/// Syscall-facing Keccak chip: VM state, syscall decode, guest memory, and local state bus.
pub struct KeccakEcallInstruction<E>(PhantomData<E>);

/// Pure Keccak-f chip. It reads/writes the Keccak-local state bus and has no guest memory ops.
pub struct KeccakCoreInstruction<E>(PhantomData<E>);

pub type KeccakInstruction<E> = KeccakCoreInstruction<E>;

fn new_memory_expr<E: ExtensionField>(cb: &mut CircuitBuilder<E>, name: String) -> MemoryExpr<E> {
    array::from_fn(|i| cb.create_witin(|| format!("{name}_{i}")).expr())
}

fn assign_memory_expr<E: ExtensionField>(
    instance: &mut [E::BaseField],
    expr: &MemoryExpr<E>,
    value: u32,
) {
    let value = Value::new_unchecked(value);
    let limbs = value.as_u16_limbs();
    for (limb_expr, limb) in expr.iter().zip_eq(limbs.iter()) {
        let multilinear_extensions::Expression::WitIn(wit) = limb_expr else {
            panic!("keccak ecall state limbs must be witness columns");
        };
        instance[*wit as usize] = E::BaseField::from_u64(*limb as u64);
    }
}

impl<E: ExtensionField> Instruction<E> for KeccakEcallInstruction<E> {
    type InstructionConfig = KeccakEcallConfig<E>;
    type InsnType = InsnKind;

    fn inst_kinds() -> &'static [Self::InsnType] {
        &[InsnKind::ECALL]
    }

    fn name() -> String {
        "KeccakEcall".to_string()
    }

    fn construct_circuit(
        cb: &mut CircuitBuilder<E>,
        _param: &ProgramParams,
    ) -> Result<Self::InstructionConfig, ZKVMError> {
        let vm_state = StateInOut::construct_circuit(cb, false)?;

        let ecall_id = OpFixedRS::<_, { Platform::reg_ecall() }, false>::construct_circuit(
            cb,
            UInt::from_const_unchecked(vec![
                KECCAK_PERMUTE & LIMB_MASK,
                (KECCAK_PERMUTE >> LIMB_BITS) & LIMB_MASK,
            ])
            .register_expr(),
            vm_state.ts,
        )?;

        let state_ptr_value = MemAddr::construct_with_max_bits(cb, 2, MEM_BITS)?;
        let state_ptr = OpFixedRS::<_, { Platform::reg_arg0() }, true>::construct_circuit(
            cb,
            state_ptr_value.uint_unaligned().register_expr(),
            vm_state.ts,
        )?;

        cb.lk_fetch(&InsnRecord::new(
            vm_state.pc.expr(),
            InsnKind::ECALL.into(),
            None,
            0.into(),
            0.into(),
            0.into(),
            #[cfg(feature = "u16limb_circuit")]
            0.into(),
        ))?;

        let input_state = array::from_fn(|i| new_memory_expr(cb, format!("keccak_input_{i}")));
        let output_state = array::from_fn(|i| new_memory_expr(cb, format!("keccak_output_{i}")));

        cb.write_record(
            || "keccak_state_in",
            RAMType::Custom,
            keccak_state_record(
                vm_state.ts.expr(),
                state_ptr_value.expr_unaligned(),
                KECCAK_STATE_PHASE_INPUT,
                input_state.iter().flat_map(|word| word.iter().cloned()),
            ),
        )?;
        cb.read_record(
            || "keccak_state_out",
            RAMType::Custom,
            keccak_state_record(
                vm_state.ts.expr(),
                state_ptr_value.expr_unaligned(),
                KECCAK_STATE_PHASE_OUTPUT,
                output_state.iter().flat_map(|word| word.iter().cloned()),
            ),
        )?;

        let mem_rw = izip!(&input_state, &output_state)
            .enumerate()
            .map(|(i, (val_before, val_after))| {
                WriteMEM::construct_circuit(
                    cb,
                    state_ptr.prev_value.as_ref().unwrap().value()
                        + E::BaseField::from_u32(ByteAddr::from((i * WORD_SIZE) as u32).0).expr(),
                    val_before.clone(),
                    val_after.clone(),
                    vm_state.ts,
                )
            })
            .collect::<Result<Vec<WriteMEM>, _>>()?;

        Ok(KeccakEcallConfig {
            vm_state,
            ecall_id,
            state_ptr: (state_ptr, state_ptr_value),
            input_state,
            output_state,
            mem_rw,
        })
    }

    fn assign_instance(
        _config: &Self::InstructionConfig,
        _shard_ctx: &mut ShardContext,
        _instance: &mut [<E as ExtensionField>::BaseField],
        _lk_multiplicity: &mut LkMultiplicity,
        _step: &StepRecord,
    ) -> Result<(), ZKVMError> {
        unreachable!("we override logic in assign_instances")
    }

    fn assign_instances(
        config: &Self::InstructionConfig,
        shard_ctx: &mut ShardContext,
        num_witin: usize,
        num_structural_witin: usize,
        steps: &[StepRecord],
        step_indices: &[StepIndex],
    ) -> Result<(RMMCollections<E::BaseField>, Multiplicity<u64>), ZKVMError> {
        let lk_multiplicity = LkMultiplicity::default();
        if step_indices.is_empty() {
            return Ok((
                [
                    RowMajorMatrix::new(0, num_witin, InstancePaddingStrategy::Default),
                    RowMajorMatrix::new(0, num_structural_witin, InstancePaddingStrategy::Default),
                ],
                lk_multiplicity.into_finalize_result(),
            ));
        }

        let nthreads = max_usable_threads();
        let num_instance_per_batch = step_indices.len().div_ceil(nthreads).max(1);
        let mut raw_witin = RowMajorMatrix::<E::BaseField>::new(
            step_indices.len(),
            num_witin,
            InstancePaddingStrategy::Default,
        );
        let mut raw_structural_witin = RowMajorMatrix::<E::BaseField>::new(
            step_indices.len(),
            num_structural_witin,
            InstancePaddingStrategy::Default,
        );

        raw_witin
            .par_batch_iter_mut(num_instance_per_batch)
            .zip_eq(raw_structural_witin.par_batch_iter_mut(num_instance_per_batch))
            .zip_eq(step_indices.par_chunks(num_instance_per_batch))
            .zip(shard_ctx.get_forked())
            .flat_map(
                |(((instances, structural_instances), indices), mut shard_ctx)| {
                    let mut lk_multiplicity = lk_multiplicity.clone();
                    instances
                        .chunks_mut(num_witin)
                        .zip_eq(structural_instances.chunks_mut(num_structural_witin))
                        .zip_eq(indices.iter().copied())
                        .map(|((instance, structural_instance), idx)| {
                            *structural_instance.last_mut().unwrap() = E::BaseField::ONE;
                            let step = &steps[idx];
                            let sw = shard_ctx.syscall_witnesses.clone();
                            let ops = &step.syscall(&sw).expect("keccak syscall step");

                            config
                                .vm_state
                                .assign_instance(instance, &shard_ctx, step)?;
                            config.ecall_id.assign_op(
                                instance,
                                &mut shard_ctx,
                                &mut lk_multiplicity,
                                step.cycle(),
                                &WriteOp::new_register_op(
                                    Platform::reg_ecall(),
                                    Change::new(KECCAK_PERMUTE, KECCAK_PERMUTE),
                                    step.rs1().unwrap().previous_cycle,
                                ),
                            )?;
                            config.state_ptr.1.assign_instance(
                                instance,
                                &mut lk_multiplicity,
                                ops.reg_ops[0].value.after,
                            )?;
                            config.state_ptr.0.assign_op(
                                instance,
                                &mut shard_ctx,
                                &mut lk_multiplicity,
                                step.cycle(),
                                &ops.reg_ops[0],
                            )?;

                            for (i, (writer, op)) in
                                config.mem_rw.iter().zip_eq(&ops.mem_ops).enumerate()
                            {
                                assign_memory_expr::<E>(
                                    instance,
                                    &config.input_state[i],
                                    op.value.before,
                                );
                                assign_memory_expr::<E>(
                                    instance,
                                    &config.output_state[i],
                                    op.value.after,
                                );
                                writer.assign_op(
                                    instance,
                                    &mut shard_ctx,
                                    &mut lk_multiplicity,
                                    step.cycle(),
                                    op,
                                )?;
                            }
                            lk_multiplicity.fetch(step.pc().before.0);
                            Ok(())
                        })
                        .collect::<Vec<_>>()
                },
            )
            .collect::<Result<(), ZKVMError>>()?;

        raw_witin.padding_by_strategy();
        raw_structural_witin.padding_by_strategy();
        Ok((
            [raw_witin, raw_structural_witin],
            lk_multiplicity.into_finalize_result(),
        ))
    }

    fn collect_lk_and_shardram(
        _config: &Self::InstructionConfig,
        shard_ctx: &mut ShardContext,
        _lk_multiplicity: &mut LkMultiplicity,
        step: &StepRecord,
    ) -> Result<(), ZKVMError> {
        let syscall_witnesses = shard_ctx.syscall_witnesses.clone();
        let ops = step
            .syscall(&syscall_witnesses)
            .expect("keccak syscall step");

        shard_ctx.send(
            RAMType::Register,
            Platform::register_vma(Platform::reg_ecall()).into(),
            Platform::reg_ecall() as u64,
            step.cycle() + ceno_emul::FullTracer::SUBCYCLE_RS1,
            step.rs1().unwrap().previous_cycle,
            KECCAK_PERMUTE,
            None,
        );
        shard_ctx.send(
            RAMType::Register,
            ops.reg_ops[0].addr,
            Platform::reg_arg0() as u64,
            step.cycle() + ceno_emul::FullTracer::SUBCYCLE_RD,
            ops.reg_ops[0].previous_cycle,
            ops.reg_ops[0].value.after,
            None,
        );
        for op in &ops.mem_ops {
            shard_ctx.send(
                RAMType::Memory,
                op.addr,
                op.addr.baddr().0 as u64,
                step.cycle() + ceno_emul::FullTracer::SUBCYCLE_MEM,
                op.previous_cycle,
                op.value.after,
                Some(op.value.before),
            );
        }

        Ok(())
    }
}

impl<E: ExtensionField> Instruction<E> for KeccakCoreInstruction<E> {
    type InstructionConfig = KeccakCoreConfig<E>;
    type InsnType = InsnKind;

    fn inst_kinds() -> &'static [Self::InsnType] {
        &[InsnKind::ECALL]
    }

    fn name() -> String {
        "KeccakCore".to_string()
    }

    fn construct_circuit(
        _circuit_builder: &mut CircuitBuilder<E>,
        _param: &ProgramParams,
    ) -> Result<Self::InstructionConfig, ZKVMError> {
        unimplemented!()
    }

    fn build_gkr_iop_circuit(
        cb: &mut CircuitBuilder<E>,
        _param: &ProgramParams,
    ) -> Result<(Self::InstructionConfig, GKRCircuit<E>), ZKVMError> {
        let mut layout =
            <KeccakLayout<E> as ProtocolBuilder<E>>::build_layer_logic(cb, KeccakParams {})?;
        let chip = layout.finalize(Self::name(), cb);
        Ok((KeccakCoreConfig { layout }, chip.gkr_circuit()))
    }

    fn generate_fixed_traces(
        config: &Self::InstructionConfig,
        num_fixed: usize,
    ) -> Option<RowMajorMatrix<E::BaseField>> {
        let fixed = config.layout.fixed_witness_group();
        assert_eq!(fixed.width(), num_fixed);
        Some(fixed)
    }

    fn assign_instance(
        _config: &Self::InstructionConfig,
        _shard_ctx: &mut ShardContext,
        _instance: &mut [<E as ExtensionField>::BaseField],
        _lk_multiplicity: &mut LkMultiplicity,
        _step: &StepRecord,
    ) -> Result<(), ZKVMError> {
        unreachable!("we override logic in assign_instances")
    }

    fn assign_instances(
        config: &Self::InstructionConfig,
        shard_ctx: &mut ShardContext,
        num_witin: usize,
        num_structural_witin: usize,
        steps: &[StepRecord],
        step_indices: &[StepIndex],
    ) -> Result<(RMMCollections<E::BaseField>, Multiplicity<u64>), ZKVMError> {
        #[cfg(feature = "gpu")]
        {
            use crate::instructions::gpu::chips::keccak::gpu_assign_keccak_instances;
            if let Some(result) = gpu_assign_keccak_instances::<E>(
                config,
                shard_ctx,
                num_witin,
                num_structural_witin,
                steps,
                step_indices,
            )? {
                return Ok(result);
            }
        }

        let mut lk_multiplicity = LkMultiplicity::default();
        if step_indices.is_empty() {
            return Ok((
                [
                    RowMajorMatrix::new(0, num_witin, InstancePaddingStrategy::Default),
                    RowMajorMatrix::new(0, num_structural_witin, InstancePaddingStrategy::Default),
                ],
                lk_multiplicity.into_finalize_result(),
            ));
        }

        let rotation = KECCAK_ROUNDS.next_power_of_two().ilog2() as usize;
        let mut raw_witin = RowMajorMatrix::<E::BaseField>::new_by_rotation(
            step_indices.len(),
            rotation,
            num_witin,
            InstancePaddingStrategy::Default,
        );
        let mut raw_structural_witin = RowMajorMatrix::<E::BaseField>::new_by_rotation(
            step_indices.len(),
            rotation,
            num_structural_witin,
            InstancePaddingStrategy::Default,
        );

        let current_shard_offset_cycle = shard_ctx.current_shard_offset_cycle();
        let instances: Vec<KeccakInstance> = step_indices
            .iter()
            .map(|&idx| -> KeccakInstance {
                let step = &steps[idx];
                let syscall = step.syscall(&shard_ctx.syscall_witnesses).unwrap();
                let instance: Vec<u32> = syscall
                    .mem_ops
                    .iter()
                    .map(|op| op.value.before)
                    .collect_vec();
                KeccakInstance {
                    state: KeccakStateInstance {
                        state_ptr_address: ByteAddr::from(syscall.reg_ops[0].value.after),
                        cur_ts: step.cycle() - current_shard_offset_cycle,
                        read_ts: [Cycle::default(); KECCAK_INPUT32_SIZE],
                    },
                    witin: KeccakWitInstance {
                        instance: instance.try_into().unwrap(),
                    },
                }
            })
            .collect_vec();

        config.layout.phase1_witness_group(
            KeccakTrace { instances },
            [&mut raw_witin, &mut raw_structural_witin],
            &mut lk_multiplicity,
        );

        raw_witin.padding_by_strategy();
        raw_structural_witin.padding_by_strategy();
        Ok((
            [raw_witin, raw_structural_witin],
            lk_multiplicity.into_finalize_result(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        circuit_builder::{CircuitBuilder, ConstraintSystem},
        e2e::ShardContext,
        structs::ProgramParams,
    };
    use ff_ext::{BabyBearExt4, FieldFrom};
    use multilinear_extensions::utils::eval_by_expr_with_instance;

    type E = BabyBearExt4;

    fn build_counts<I: Instruction<E>>() -> (usize, usize, usize, usize) {
        let mut cs = ConstraintSystem::<E>::new(|| I::name());
        let mut cb = CircuitBuilder::new(&mut cs);
        let (_, gkr_circuit) =
            I::build_gkr_iop_circuit(&mut cb, &ProgramParams::default()).expect("build circuit");
        let reads = cb.cs.r_expressions.len() + cb.cs.r_table_expressions.len();
        let writes = cb.cs.w_expressions.len() + cb.cs.w_table_expressions.len();
        let lks = cb.cs.lk_expressions.len() + cb.cs.lk_table_expressions.len();
        let max_selector_groups = gkr_circuit
            .layers
            .iter()
            .map(|layer| layer.out_sel_and_eval_exprs.len())
            .max()
            .unwrap_or_default();
        (reads, writes, lks, max_selector_groups)
    }

    fn eval_expr(
        expr: &multilinear_extensions::Expression<E>,
        wit_row: &[<E as ExtensionField>::BaseField],
        structural_row: &[<E as ExtensionField>::BaseField],
    ) -> E {
        let wit_row = wit_row.iter().copied().map(E::from).collect_vec();
        let structural_row = structural_row.iter().copied().map(E::from).collect_vec();
        let challenges = [E::from_v(7), E::from_v(11)];
        eval_by_expr_with_instance::<E>(&[], &wit_row, &structural_row, &[], &challenges, expr)
            .unwrap_right()
    }

    fn selected_row(
        values: &[<E as ExtensionField>::BaseField],
        width: usize,
        row_index: usize,
    ) -> &[<E as ExtensionField>::BaseField] {
        &values[row_index * width..][..width]
    }

    #[test]
    fn keccak_split_accounting_keeps_memory_out_of_core() {
        let (ecall_reads, ecall_writes, ecall_lks, _) = build_counts::<KeccakEcallInstruction<E>>();
        let (core_reads, core_writes, _, max_core_selector_groups) =
            build_counts::<KeccakCoreInstruction<E>>();

        assert_eq!(core_reads, 1, "core should only read the input state bus");
        assert_eq!(
            core_writes, 1,
            "core should only write the output state bus"
        );
        assert!(
            max_core_selector_groups < 1024,
            "core sumcheck groups grew to {max_core_selector_groups}"
        );

        assert!(
            ecall_reads >= KECCAK_INPUT32_SIZE + 3,
            "ecall should own guest memory/register reads"
        );
        assert!(
            ecall_writes >= KECCAK_INPUT32_SIZE + 3,
            "ecall should own guest memory/register writes"
        );
        assert!(
            ecall_lks >= KECCAK_INPUT32_SIZE + 2,
            "ecall should own timestamp/register LT lookups"
        );
    }

    #[test]
    fn keccak_state_bus_records_match_between_split_chips() {
        let (step, _program, syscall_witnesses) = ceno_emul::test_utils::keccak_step();
        let steps = vec![step];
        let step_indices = vec![0];

        let mut mem_cs = ConstraintSystem::<E>::new(|| "keccak_ecall");
        let mut mem_cb = CircuitBuilder::new(&mut mem_cs);
        let (mem_config, _) = KeccakEcallInstruction::<E>::build_gkr_iop_circuit(
            &mut mem_cb,
            &ProgramParams::default(),
        )
        .expect("build ecall circuit");
        let mem_num_witin = mem_cb.cs.num_witin as usize;
        let mem_num_structural_witin = mem_cb.cs.num_structural_witin as usize;

        let mut perm_cs = ConstraintSystem::<E>::new(|| "keccak_core");
        let mut perm_cb = CircuitBuilder::new(&mut perm_cs);
        let (perm_config, _) = KeccakCoreInstruction::<E>::build_gkr_iop_circuit(
            &mut perm_cb,
            &ProgramParams::default(),
        )
        .expect("build core circuit");
        let perm_num_witin = perm_cb.cs.num_witin as usize;
        let perm_num_structural_witin = perm_cb.cs.num_structural_witin as usize;

        let mut mem_shard_ctx = ShardContext::default();
        mem_shard_ctx.syscall_witnesses = std::sync::Arc::new(syscall_witnesses.clone());
        let (mem_rmms, _) = KeccakEcallInstruction::<E>::assign_instances(
            &mem_config,
            &mut mem_shard_ctx,
            mem_num_witin,
            mem_num_structural_witin,
            &steps,
            &step_indices,
        )
        .expect("assign ecall witness");

        let mut perm_shard_ctx = ShardContext::default();
        perm_shard_ctx.syscall_witnesses = std::sync::Arc::new(syscall_witnesses);
        let (perm_rmms, _) = KeccakCoreInstruction::<E>::assign_instances(
            &perm_config,
            &mut perm_shard_ctx,
            perm_num_witin,
            perm_num_structural_witin,
            &steps,
            &step_indices,
        )
        .expect("assign core witness");

        let mem_wit_row = selected_row(mem_rmms[0].values(), mem_num_witin, 0);
        let mem_structural_row =
            selected_row(mem_rmms[1].values(), mem_num_structural_witin.max(1), 0);

        let first_row = perm_config
            .layout
            .selector_type_layout
            .sel_first
            .as_ref()
            .unwrap()
            .sparse_indices()[0];
        let last_row = perm_config
            .layout
            .selector_type_layout
            .sel_last
            .as_ref()
            .unwrap()
            .sparse_indices()[0];
        let perm_wit_first = selected_row(perm_rmms[0].values(), perm_num_witin, first_row);
        let perm_structural_first =
            selected_row(perm_rmms[1].values(), perm_num_structural_witin, first_row);
        let perm_wit_last = selected_row(perm_rmms[0].values(), perm_num_witin, last_row);
        let perm_structural_last =
            selected_row(perm_rmms[1].values(), perm_num_structural_witin, last_row);

        let mem_in_write = mem_cb
            .cs
            .w_expressions_namespace_map
            .iter()
            .position(|name| name.contains("keccak_state_in"))
            .expect("ecall input bus write");
        let mem_out_read = mem_cb
            .cs
            .r_expressions_namespace_map
            .iter()
            .position(|name| name.contains("keccak_state_out"))
            .expect("ecall output bus read");
        let perm_in_read = perm_cb
            .cs
            .r_expressions_namespace_map
            .iter()
            .position(|name| name.contains("keccak_state_in"))
            .expect("core input bus read");
        let perm_out_write = perm_cb
            .cs
            .w_expressions_namespace_map
            .iter()
            .position(|name| name.contains("keccak_state_out"))
            .expect("core output bus write");

        assert_eq!(
            eval_expr(
                &mem_cb.cs.w_expressions[mem_in_write],
                mem_wit_row,
                mem_structural_row,
            ),
            eval_expr(
                &perm_cb.cs.r_expressions[perm_in_read],
                perm_wit_first,
                perm_structural_first,
            ),
            "input Keccak-state bus record mismatch",
        );
        assert_eq!(
            eval_expr(
                &mem_cb.cs.r_expressions[mem_out_read],
                mem_wit_row,
                mem_structural_row,
            ),
            eval_expr(
                &perm_cb.cs.w_expressions[perm_out_write],
                perm_wit_last,
                perm_structural_last,
            ),
            "output Keccak-state bus record mismatch",
        );
    }
}
