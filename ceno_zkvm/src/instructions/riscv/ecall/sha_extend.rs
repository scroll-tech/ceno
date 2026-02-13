use std::{array, marker::PhantomData};

use ceno_emul::{Change, InsnKind, Platform, SHA_EXTEND, StepRecord, WORD_SIZE, WriteOp};
use ff_ext::{ExtensionField, FieldInto};
use gkr_iop::{
    ProtocolBuilder, ProtocolWitnessGenerator, gkr::GKRCircuit,
    utils::lk_multiplicity::Multiplicity,
};
use itertools::{Itertools, izip};
use multilinear_extensions::{ToExpr, WitIn, util::max_usable_threads};
use p3::matrix::Matrix;
use rayon::{
    iter::{IndexedParallelIterator, ParallelIterator},
    slice::ParallelSlice,
};
use witness::{InstancePaddingStrategy, RowMajorMatrix, set_val};

use crate::{
    chip_handler::general::InstFetch,
    circuit_builder::CircuitBuilder,
    e2e::ShardContext,
    error::ZKVMError,
    instructions::{
        Instruction,
        riscv::{
            constants::{LIMB_BITS, LIMB_MASK, MEM_BITS, UINT_LIMBS, UInt},
            ecall_base::OpFixedRS,
            insn_base::{MemAddr, StateInOut, WriteMEM},
        },
    },
    precompiles::{ShaExtendInstance, ShaExtendLayout, ShaExtendTrace, ShaExtendWitInstance},
    structs::ProgramParams,
    tables::{InsnRecord, RMMCollections},
    witness::LkMultiplicity,
};

#[derive(Debug)]
pub struct EcallShaExtendConfig<E: ExtensionField> {
    pub layout: ShaExtendLayout<E>,
    vm_state: StateInOut<E>,
    ecall_id: OpFixedRS<E, { Platform::reg_ecall() }, false>,
    state_ptr: (OpFixedRS<E, { Platform::reg_arg0() }, true>, MemAddr<E>),
    old_value: [WitIn; UINT_LIMBS],
    mem_rw: Vec<WriteMEM>,
}

/// ShaExtendInstruction can handle any instruction and produce its side-effects.
pub struct ShaExtendInstruction<E>(PhantomData<E>);

impl<E: ExtensionField> Instruction<E> for ShaExtendInstruction<E> {
    type InstructionConfig = EcallShaExtendConfig<E>;
    type InsnType = InsnKind;

    fn inst_kinds() -> &'static [Self::InsnType] {
        &[InsnKind::ECALL]
    }

    fn name() -> String {
        "Ecall_ShaExtend".to_string()
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
        let vm_state = StateInOut::construct_circuit(cb, false)?;

        let ecall_id = OpFixedRS::<_, { Platform::reg_ecall() }, false>::construct_circuit(
            cb,
            UInt::from_const_unchecked(vec![
                SHA_EXTEND & LIMB_MASK,
                (SHA_EXTEND >> LIMB_BITS) & LIMB_MASK,
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

        // fetch
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

        let layout =
            <ShaExtendLayout<E> as gkr_iop::ProtocolBuilder<E>>::build_layer_logic(cb, ())?;

        let old_value =
            array::from_fn(|i| cb.create_witin(|| format!("sha256 extend old_mem_value_{}", i)));
        let offset = [-2, -7, -15, -16];
        let mut mem_rw = izip!(offset, &layout.input32_exprs)
            .map(|(offset, val_before)| {
                WriteMEM::construct_circuit(
                    cb,
                    state_ptr.prev_value.as_ref().unwrap().value() + offset * WORD_SIZE as i32,
                    val_before.clone(),
                    val_before.clone(),
                    vm_state.ts,
                )
            })
            .collect::<Result<Vec<_>, ZKVMError>>()?;

        mem_rw.push(WriteMEM::construct_circuit(
            cb,
            state_ptr.prev_value.as_ref().unwrap().value(),
            [old_value[0].expr(), old_value[1].expr()],
            layout.output32_expr.clone(),
            vm_state.ts,
        )?);

        let chip = layout.finalize(Self::name(), cb);

        let circuit = chip.gkr_circuit();

        Ok((
            EcallShaExtendConfig {
                layout,
                vm_state,
                ecall_id,
                state_ptr: (state_ptr, state_ptr_value),
                old_value,
                mem_rw,
            },
            circuit,
        ))
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
    ) -> Result<(RMMCollections<E::BaseField>, Multiplicity<u64>), ZKVMError> {
        let mut lk_multiplicity = LkMultiplicity::default();
        if steps.is_empty() {
            return Ok((
                [
                    RowMajorMatrix::new(0, num_witin, InstancePaddingStrategy::Default),
                    RowMajorMatrix::new(0, num_structural_witin, InstancePaddingStrategy::Default),
                ],
                lk_multiplicity.into_finalize_result(),
            ));
        }

        let num_instances = steps.len();
        let nthreads = max_usable_threads();
        let num_instance_per_batch = num_instances.div_ceil(nthreads).max(1);

        let mut raw_witin = RowMajorMatrix::<E::BaseField>::new(
            num_instances,
            num_witin,
            InstancePaddingStrategy::Default,
        );
        let mut raw_structural_witin = RowMajorMatrix::<E::BaseField>::new(
            num_instances,
            num_structural_witin,
            InstancePaddingStrategy::Default,
        );

        let raw_witin_iter = raw_witin.par_batch_iter_mut(num_instance_per_batch);
        let shard_ctx_vec = shard_ctx.get_forked();

        raw_witin_iter
            .zip_eq(steps.par_chunks(num_instance_per_batch))
            .zip(shard_ctx_vec)
            .flat_map(|((instances, steps), mut shard_ctx)| {
                let mut lk_multiplicity = lk_multiplicity.clone();

                instances
                    .chunks_mut(num_witin)
                    .zip_eq(steps)
                    .map(|(instance, step)| {
                        let ops = step.syscall().expect("syscall step");

                        // vm_state
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
                                Change::new(SHA_EXTEND, SHA_EXTEND),
                                step.rs1().unwrap().previous_cycle,
                            ),
                        )?;

                        // assign state_ptr
                        config.state_ptr.1.assign_instance(
                            instance,
                            &mut lk_multiplicity,
                            ops.reg_ops[0].value.before,
                        )?;
                        config.state_ptr.0.assign_op(
                            instance,
                            &mut shard_ctx,
                            &mut lk_multiplicity,
                            step.cycle(),
                            &ops.reg_ops[0],
                        )?;

                        let write_op = ops.mem_ops.last().expect("sha_extend write op");
                        set_val!(
                            instance,
                            config.old_value[0],
                            (write_op.value.before & LIMB_MASK) as u64
                        );
                        set_val!(
                            instance,
                            config.old_value[1],
                            (write_op.value.before >> LIMB_BITS) as u64
                        );

                        // assign mem_rw
                        for (writer, op) in config.mem_rw.iter().zip_eq(&ops.mem_ops) {
                            writer.assign_op(
                                instance,
                                &mut shard_ctx,
                                &mut lk_multiplicity,
                                step.cycle(),
                                op,
                            )?;
                        }
                        // fetch
                        lk_multiplicity.fetch(step.pc().before.0);
                        Ok(())
                    })
                    .collect::<Vec<_>>()
            })
            .collect::<Result<(), ZKVMError>>()?;

        let instances = steps
            .iter()
            .map(|step| -> ShaExtendInstance {
                let ops = step.syscall().expect("syscall step");
                let w_i_minus_2 = ops.mem_ops[0].value.before;
                let w_i_minus_7 = ops.mem_ops[1].value.before;
                let w_i_minus_15 = ops.mem_ops[2].value.before;
                let w_i_minus_16 = ops.mem_ops[3].value.before;
                ShaExtendInstance {
                    witin: ShaExtendWitInstance {
                        w_i_minus_2,
                        w_i_minus_7,
                        w_i_minus_15,
                        w_i_minus_16,
                    },
                }
            })
            .collect_vec();

        config.layout.phase1_witness_group(
            ShaExtendTrace { instances },
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
