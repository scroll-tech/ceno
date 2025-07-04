use std::marker::PhantomData;

use ceno_emul::{ByteAddr, InsnKind, PC_STEP_SIZE, StepRecord, Tracer};
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
    chip_handler::GlobalStateRegisterMachineChipOperations,
    circuit_builder::CircuitBuilder,
    error::ZKVMError,
    instructions::{
        Instruction,
        riscv::{
            constants::UInt,
            insn_base::{ReadRS1, ReadRS2},
        },
    },
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

    fn construct_circuit(cb: &mut CircuitBuilder<E>) -> Result<Self::InstructionConfig, ZKVMError> {
        // construct keccak gkr-iop circuit
        let params = gkr_iop::precompiles::KeccakParams {};
        let (layout, chip) = <KeccakLayout<E> as gkr_iop::ProtocolBuilder<E>>::build(params);
        let circuit = chip.gkr_circuit();

        // TODO FIXME below circuit construction are out-of-sync with gkr-iop circuit, because both constrain system are separated
        // TODO FIXME and manage constrains/witness in isolated struct
        // constrain vmstate
        // state in and out
        let cur_ts = layout.layer_exprs.wits.cur_ts[0].expr();
        let next_ts = cur_ts.clone() + Tracer::SUBCYCLES_PER_INSN;
        let pc = layout.layer_exprs.wits.pc[0].expr();
        let next_pc = pc.expr() + PC_STEP_SIZE;
        cb.state_in(pc.clone(), cur_ts.clone())?;
        cb.state_out(next_pc, next_ts)?;

        // fetch
        cb.lk_fetch(&InsnRecord::new(
            pc.clone(),
            InsnKind::ECALL.into(),
            Some(E::BaseField::ZERO.expr()),
            E::BaseField::ZERO.expr(),
            E::BaseField::ZERO.expr(),
            E::BaseField::ZERO.expr(),
        ))?;

        // TODO register read are not under same constrain system
        // rs1: ecall code
        let rs1_read = UInt::new_unchecked(|| "rs1_read", cb)?;
        let _rs1_op = ReadRS1::construct_circuit(
            cb,
            rs1_read.register_expr(),
            layout.layer_exprs.wits.cur_ts[0],
        )?;

        // rs2: state ptr
        let rs2_read = UInt::new_unchecked(|| "rs2_read", cb)?;
        let _rs2_op = ReadRS2::construct_circuit(
            cb,
            rs2_read.register_expr(),
            layout.layer_exprs.wits.cur_ts[0],
        )?;

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
