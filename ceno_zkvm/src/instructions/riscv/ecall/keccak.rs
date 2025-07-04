use std::marker::PhantomData;

use ceno_emul::{ByteAddr, InsnKind, PC_STEP_SIZE, Platform, StepRecord, Tracer};
use ff_ext::ExtensionField;
use gkr_iop::{
    ProtocolWitnessGenerator,
    gkr::GKRCircuit,
    precompiles::{KECCAK_INPUT32_SIZE, KeccakLayout, KeccakTrace},
};
use itertools::Itertools;
use multilinear_extensions::ToExpr;
use p3::field::FieldAlgebra;
use witness::RowMajorMatrix;

use crate::{
    chip_handler::{GlobalStateRegisterMachineChipOperations, general::InstFetch},
    circuit_builder::CircuitBuilder,
    error::ZKVMError,
    instructions::{
        Instruction,
        riscv::{
            constants::UInt,
            ecall_base::WriteFixedRS,
            insn_base::{ReadRS1, ReadRS2, StateInOut, WriteRD},
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

        // construct keccak gkr-iop circuit
        let params = gkr_iop::precompiles::KeccakParams {};
        let (layout, chip) = <KeccakLayout<E> as gkr_iop::ProtocolBuilder<E>>::build(cb, params);
        let circuit = chip.gkr_circuit();

        Ok(EcallKeccakConfig { circuit, layout })
    }

    fn assign_instances(
        config: &Self::InstructionConfig,
        _num_witin: usize,
        steps: Vec<StepRecord>,
    ) -> Result<(RowMajorMatrix<E::BaseField>, LkMultiplicity), ZKVMError> {
        let mut lk_multiplicity = LkMultiplicity::default();
        let instances = steps
            .iter()
            .map(|step| {
                step.syscall()
                    .unwrap()
                    .mem_ops
                    .iter()
                    .map(|op| op.value.before)
                    .collect_vec()
                    .try_into()
                    .unwrap()
            })
            .collect_vec();
        let num_instances = instances.len();

        let mut raw_witin = config.layout.phase1_witness_group(
            KeccakTrace {
                instances,
                ram_start_addr: vec![ByteAddr::from(0); num_instances],
                read_ts: vec![[0; KECCAK_INPUT32_SIZE]; num_instances],
                cur_ts: vec![0; num_instances],
            },
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
