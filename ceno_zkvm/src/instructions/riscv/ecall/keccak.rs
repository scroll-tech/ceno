use std::{array, marker::PhantomData};

use ceno_emul::{ByteAddr, Change, Cycle, InsnKind, Platform, StepRecord};
use ff_ext::ExtensionField;
use gkr_iop::{
    ProtocolWitnessGenerator,
    gkr::GKRCircuit,
    precompiles::{
        KECCAK_INPUT32_SIZE, KECCAK_WIT_SIZE, KeccakInOutCols, KeccakInstance, KeccakLayout,
        KeccakStateInstance, KeccakTrace, KeccakWitInstance,
    },
};
use itertools::Itertools;
use multilinear_extensions::{ToExpr, WitIn, util::max_usable_threads};
use p3::field::FieldAlgebra;
use witness::{InstancePaddingStrategy, RowMajorMatrix};

use crate::{
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
    structs::ProgramParams,
    tables::InsnRecord,
    witness::LkMultiplicity,
};

#[derive(Debug)]
pub struct EcallKeccakConfig<E: ExtensionField> {
    pub circuit: GKRCircuit<E>,
    pub layout: KeccakLayout<E>,
    _vm_state: StateInOut<E>,
    _ecall_id: WriteFixedRS<E, { Platform::reg_ecall() }>,
    _state_ptr: WriteFixedRS<E, { Platform::reg_arg0() }>,
    _mem_rw: Vec<(Change<WitIn>, WriteMEM)>,
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

        let ecall_id = WriteFixedRS::<_, { Platform::reg_ecall() }>::construct_circuit(
            cb,
            ecall_id_value.register_expr(),
            vm_state.ts,
        )?;
        let state_ptr = WriteFixedRS::<_, { Platform::reg_arg0() }>::construct_circuit(
            cb,
            state_ptr_value.register_expr(),
            vm_state.ts,
        )?;

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
                    state_ptr.prev_value.value()
                        + E::BaseField::from_canonical_u32(i as u32).expr(),
                    val_before.expr(),
                    val_after.expr(),
                    vm_state.ts,
                )
                .map(|writer| (Change::new(val_before, val_after), writer))
            })
            .collect::<Result<Vec<(Change<WitIn>, WriteMEM)>, _>>()?;

        // construct keccak gkr-iop circuit
        let params = gkr_iop::precompiles::KeccakParams {
            io: KeccakInOutCols {
                input32: array::from_fn(|i| mem_rw[i].0.before.expr()),
                output32: array::from_fn(|i| mem_rw[i].0.after.expr()),
            },
        };
        let (layout, chip) = <KeccakLayout<E> as gkr_iop::ProtocolBuilder<E>>::build(cb, params)?;
        let circuit = chip.gkr_circuit();

        Ok(EcallKeccakConfig {
            circuit,
            layout,
            _vm_state: vm_state,
            _ecall_id: ecall_id,
            _state_ptr: state_ptr,
            _mem_rw: mem_rw,
        })
    }

    fn assign_instances(
        config: &Self::InstructionConfig,
        num_witin: usize,
        steps: Vec<StepRecord>,
    ) -> Result<(RowMajorMatrix<E::BaseField>, LkMultiplicity), ZKVMError> {
        let mut lk_multiplicity = LkMultiplicity::default();
        if steps.is_empty() {
            return Ok((
                RowMajorMatrix::new(0, KECCAK_WIT_SIZE, InstancePaddingStrategy::Default),
                lk_multiplicity,
            ));
        }
        let nthreads = max_usable_threads();
        let _num_instance_per_batch = if steps.len() > 256 {
            config
                .layout
                .phase1_witin_rmm_height(steps.len())
                .div_ceil(nthreads)
        } else {
            config.layout.phase1_witin_rmm_height(steps.len())
        }
        .max(1);

        let mut raw_witin = RowMajorMatrix::<E::BaseField>::new(
            config.layout.phase1_witin_rmm_height(steps.len()),
            num_witin,
            InstancePaddingStrategy::Default,
        );

        // 1st pass: assign witness outside of gkr-iop scope
        // raw_witin
        //     .values
        //     .par_chunks_mut(KECCAK_WIT_SIZE * KECCAK_ROUNDS.next_power_of_two())
        //     .zip(steps.par_chunks(num_instance_per_batch))
        //     .flat_map(|(instances, steps)| {
        //         let mut lk_multiplicity = lk_multiplicity.clone();
        //         instances
        //             .chunks_mut(num_witin)
        //             .zip(steps)
        //             .map(|(instance, step)| {
        //                 // Registers
        //                 // config.ecall_id.assign_op();
        //                 if let Some((rs1_op, rs1_read)) = &self.rs1 {
        //                     rs1_op.assign_instance(instance, lk_multiplicity, step)?;

        //                     let rs1_val =
        //                         Value::new_unchecked(step.rs1().expect("rs1 value").value);
        //                     rs1_read.assign_value(instance, rs1_val);
        //                 }
        //                 if let Some((rs2_op, rs2_read)) = &self.rs2 {
        //                     rs2_op.assign_instance(instance, lk_multiplicity, step)?;

        //                     let rs2_val =
        //                         Value::new_unchecked(step.rs2().expect("rs2 value").value);
        //                     rs2_read.assign_value(instance, rs2_val);
        //                 }
        //                 if let Some((rd_op, rd_written)) = &self.rd {
        //                     rd_op.assign_instance(instance, lk_multiplicity, step)?;

        //                     let rd_val =
        //                         Value::new_unchecked(step.rd().expect("rd value").value.after);
        //                     rd_written.assign_value(instance, rd_val);
        //                 }

        //                 // Memory
        //                 if let Some([mem_addr, mem_before, mem_after]) = &self.mem_addr_val {
        //                     let mem_op = step.memory_op().expect("memory operation");
        //                     set_val!(instance, mem_addr, u64::from(mem_op.addr));
        //                     set_val!(instance, mem_before, mem_op.value.before as u64);
        //                     set_val!(instance, mem_after, mem_op.value.after as u64);
        //                 }
        //                 if let Some(mem_read) = &self.mem_read {
        //                     mem_read.assign_instance(instance, lk_multiplicity, step)?;
        //                 }
        //                 if let Some(mem_write) = &self.mem_write {
        //                     mem_write.assign_instance::<E>(instance, lk_multiplicity, step)?;
        //                 }

        //                 // TODO assign vm state

        //                 // TODO assign ecall_id

        //                 // TODO assign state_ptr

        //                 // TODO assign mem_rw
        //             })
        //             .collect::<Vec<_>>()
        //     })
        //     .collect::<Result<(), ZKVMError>>()?;

        let instances: Vec<KeccakInstance> = steps
            .iter()
            .map(|step| -> KeccakInstance {
                let (witin, prev_ts): (Vec<u32>, Vec<Cycle>) = step
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
                        instance: witin.try_into().unwrap(),
                    },
                }
            })
            .collect_vec();

        config.layout.phase1_witness_group(
            KeccakTrace { instances },
            &mut raw_witin,
            &mut lk_multiplicity,
        );

        raw_witin.padding_by_strategy();
        Ok((raw_witin, lk_multiplicity))
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
