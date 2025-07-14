use std::{array, marker::PhantomData};

use ceno_emul::{ByteAddr, Change, Cycle, InsnKind, Platform, StepRecord};
use ff_ext::{ExtensionField, FieldInto};
use gkr_iop::{ProtocolWitnessGenerator, gkr::GKRCircuit};
use itertools::Itertools;
use multilinear_extensions::{ToExpr, WitIn, util::max_usable_threads};
use p3::{field::FieldAlgebra, matrix::Matrix};
use rayon::{
    iter::{IndexedParallelIterator, ParallelIterator},
    slice::ParallelSlice,
};
use witness::{InstancePaddingStrategy, RowMajorMatrix, set_val};

use crate::{
    Value,
    chip_handler::general::InstFetch,
    circuit_builder::CircuitBuilder,
    error::ZKVMError,
    instructions::{
        Instruction,
        riscv::{
            constants::UInt,
            ecall_base::WriteFixedRS,
            insn_base::{StateInOut, WriteMEM},
        },
    },
    precompiles::{
        KECCAK_INPUT32_SIZE, KECCAK_ROUNDS, KeccakInOutCols, KeccakInstance, KeccakLayout,
        KeccakParams, KeccakStateInstance, KeccakTrace, KeccakWitInstance,
    },
    structs::ProgramParams,
    tables::{InsnRecord, RMMCollections},
    witness::LkMultiplicity,
};

#[derive(Debug)]
pub struct EcallKeccakConfig<E: ExtensionField> {
    pub circuit: GKRCircuit<E>,
    pub layout: KeccakLayout<E>,
    vm_state: StateInOut<E>,
    ecall_id: (WriteFixedRS<E, { Platform::reg_ecall() }>, UInt<E>),
    state_ptr: (WriteFixedRS<E, { Platform::reg_arg0() }>, UInt<E>),
    mem_rw: Vec<(Change<WitIn>, WriteMEM)>,
}

/// KeccakInstruction can handle any instruction and produce its side-effects.
pub struct KeccakInstruction<E>(PhantomData<E>);

impl<E: ExtensionField> Instruction<E> for KeccakInstruction<E> {
    type InstructionConfig = EcallKeccakConfig<E>;

    fn name() -> String {
        "Ecall_Keccak".to_string()
    }

    /// giving config, extract optional gkr circuit
    fn extract_gkr_iop_circuit(
        config: &mut Self::InstructionConfig,
    ) -> Result<Option<GKRCircuit<E>>, ZKVMError> {
        Ok(Some(config.circuit.clone()))
    }

    fn construct_circuit(
        cb: &mut CircuitBuilder<E>,
        _params: &ProgramParams,
    ) -> Result<Self::InstructionConfig, ZKVMError> {
        // constrain vmstate
        let vm_state = StateInOut::construct_circuit(cb, false)?;

        let ecall_id_value = UInt::new_unchecked(|| "ecall_id", cb)?;
        let state_ptr_value = UInt::new_unchecked(|| "state_ptr", cb)?;

        let ecall_id = (
            WriteFixedRS::<_, { Platform::reg_ecall() }>::construct_circuit(
                cb,
                ecall_id_value.register_expr(),
                vm_state.ts,
            )?,
            ecall_id_value,
        );
        let state_ptr = (
            WriteFixedRS::<_, { Platform::reg_arg0() }>::construct_circuit(
                cb,
                state_ptr_value.register_expr(),
                vm_state.ts,
            )?,
            state_ptr_value,
        );

        // fetch
        cb.lk_fetch(&InsnRecord::new(
            vm_state.pc.expr(),
            InsnKind::ECALL.into(),
            Some(E::BaseField::ZERO.expr()),
            E::BaseField::ZERO.expr(),
            E::BaseField::ZERO.expr(),
            E::BaseField::ZERO.expr(),
        ))?;

        // memory rw, for we in-place update
        let mem_rw = (0..KECCAK_INPUT32_SIZE)
            .map(|i| {
                let val_before = cb.create_witin(|| format!("mem_before_{}_READ_ARG", i));
                let val_after = cb.create_witin(|| format!("mem_after_{}_WRITE_ARG", i));
                WriteMEM::construct_circuit(
                    cb,
                    // mem address := state_ptr + i
                    state_ptr.0.prev_value.value()
                        + E::BaseField::from_canonical_u32(i as u32).expr(),
                    val_before.expr(),
                    val_after.expr(),
                    vm_state.ts,
                )
                .map(|writer| (Change::new(val_before, val_after), writer))
            })
            .collect::<Result<Vec<(Change<WitIn>, WriteMEM)>, _>>()?;

        // construct keccak gkr-iop circuit
        let params = KeccakParams {
            io: KeccakInOutCols {
                input32: array::from_fn(|i| mem_rw[i].0.before.expr()),
                output32: array::from_fn(|i| mem_rw[i].0.after.expr()),
            },
        };
        let (layout, chip) =
            <KeccakLayout<E> as gkr_iop::ProtocolBuilder<E>>::build_gkr_chip(cb, params)?;
        let circuit = chip.gkr_circuit();

        Ok(EcallKeccakConfig {
            circuit,
            layout,
            vm_state,
            ecall_id,
            state_ptr,
            mem_rw,
        })
    }

    fn generate_fixed_traces(
        config: &Self::InstructionConfig,
        num_fixed: usize,
    ) -> Option<RowMajorMatrix<E::BaseField>> {
        let fixed = config.layout.fixed_witness_group();
        assert_eq!(fixed.width(), num_fixed);
        Some(fixed)
    }

    fn assign_instances(
        config: &Self::InstructionConfig,
        num_witin: usize,
        num_structural_witin: usize,
        steps: Vec<StepRecord>,
    ) -> Result<(RMMCollections<E::BaseField>, LkMultiplicity), ZKVMError> {
        let mut lk_multiplicity = LkMultiplicity::default();
        if steps.is_empty() {
            return Ok((
                [
                    RowMajorMatrix::new(0, num_witin, InstancePaddingStrategy::Default),
                    RowMajorMatrix::new(0, num_structural_witin, InstancePaddingStrategy::Default),
                ],
                lk_multiplicity,
            ));
        }
        let nthreads = max_usable_threads();
        let num_instance_per_batch = steps.len().div_ceil(nthreads).max(1);

        let mut raw_witin = RowMajorMatrix::<E::BaseField>::new(
            config.layout.phase1_witin_rmm_height(steps.len()),
            num_witin,
            InstancePaddingStrategy::Default,
        );
        let mut raw_structural_witin = RowMajorMatrix::<E::BaseField>::new(
            config.layout.phase1_witin_rmm_height(steps.len()),
            num_witin,
            InstancePaddingStrategy::Default,
        );

        // each instance are composed of KECCAK_ROUNDS.next_power_of_two()
        let raw_witin_iter = raw_witin
            .par_batch_iter_mut(num_instance_per_batch * KECCAK_ROUNDS.next_power_of_two());

        // 1st pass: assign witness outside of gkr-iop scope
        raw_witin_iter
            .zip_eq(steps.par_chunks(num_instance_per_batch))
            .flat_map(|(instances, steps)| {
                let mut lk_multiplicity = lk_multiplicity.clone();
                instances
                    .chunks_mut(num_witin * KECCAK_ROUNDS.next_power_of_two())
                    .zip_eq(steps)
                    .map(|(instance_with_rotation, step)| {
                        let ops = &step.syscall().expect("syscall step");

                        // assign full rotation with same witness
                        for instance in instance_with_rotation.chunks_mut(num_witin) {
                            // vm_state
                            config.vm_state.assign_instance(instance, step)?;

                            //  assign ecall_id
                            config.ecall_id.1.assign_value(
                                instance,
                                Value::new_unchecked(ops.reg_ops[0].value.after),
                            );
                            config.ecall_id.0.assign_op(
                                instance,
                                &mut lk_multiplicity,
                                step.cycle(),
                                &ops.reg_ops[0],
                            )?;
                            //  assign state_ptr
                            config.state_ptr.1.assign_value(
                                instance,
                                Value::new_unchecked(ops.reg_ops[1].value.after),
                            );
                            config.state_ptr.0.assign_op(
                                instance,
                                &mut lk_multiplicity,
                                step.cycle(),
                                &ops.reg_ops[1],
                            )?;
                            // assign mem_rw
                            for ((value, writer), op) in config.mem_rw.iter().zip_eq(&ops.mem_ops) {
                                set_val!(instance, value.before, op.value.before as u64);
                                set_val!(instance, value.after, op.value.after as u64);
                                writer.assign_op(
                                    instance,
                                    &mut lk_multiplicity,
                                    step.cycle(),
                                    op,
                                )?;
                            }
                        }
                        Ok(())
                    })
                    .collect::<Vec<_>>()
            })
            .collect::<Result<(), ZKVMError>>()?;

        // second pass
        let instances: Vec<KeccakInstance> = steps
            .iter()
            .map(|step| -> KeccakInstance {
                let (instance, prev_ts): (Vec<u32>, Vec<Cycle>) = step
                    .syscall()
                    .unwrap()
                    .mem_ops
                    .iter()
                    .map(|op| (op.value.before, op.previous_cycle))
                    .unzip();
                KeccakInstance {
                    state: KeccakStateInstance {
                        state_ptr_address: ByteAddr::from(step.rs1().unwrap().value),
                        cur_ts: step.cycle(),
                        read_ts: prev_ts.try_into().unwrap(),
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
        Ok(([raw_witin, raw_structural_witin], lk_multiplicity))
    }

    fn assign_instance(
        _config: &Self::InstructionConfig,
        _instance: &mut [<E as ExtensionField>::BaseField],
        _lk_multiplicity: &mut LkMultiplicity,
        _step: &StepRecord,
    ) -> Result<(), ZKVMError> {
        unreachable!("we override logic in assign_instances")
    }
}
