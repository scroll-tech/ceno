use crate::{
    chip_handler::{RegisterChipOperations, general::PublicIOQuery},
    circuit_builder::CircuitBuilder,
    e2e::ShardContext,
    error::ZKVMError,
    gadgets::AssertLtConfig,
    instructions::{
        Instruction,
        riscv::{
            constants::{ECALL_HALT_OPCODE, EXIT_PC},
            ecall_insn::EcallInstructionConfig,
        },
    },
    structs::{ProgramParams, RAMType},
    witness::LkMultiplicity,
};
use ceno_emul::{StepRecord, Tracer};
use ff_ext::{ExtensionField, FieldInto};
use multilinear_extensions::{ToExpr, WitIn};
use p3::field::FieldAlgebra;
use std::marker::PhantomData;
use witness::set_val;

pub struct HaltConfig {
    ecall_cfg: EcallInstructionConfig,
    prev_x10_ts: WitIn,
    lt_x10_cfg: AssertLtConfig,
}

pub struct HaltInstruction<E>(PhantomData<E>);

impl<E: ExtensionField> Instruction<E> for HaltInstruction<E> {
    type InstructionConfig = HaltConfig;

    fn name() -> String {
        "ECALL_HALT".into()
    }

    fn construct_circuit(
        cb: &mut CircuitBuilder<E>,
        _params: &ProgramParams,
    ) -> Result<Self::InstructionConfig, ZKVMError> {
        let prev_x10_ts = cb.create_witin(|| "prev_x10_ts");
        let exit_code = {
            let exit_code = cb.query_exit_code()?;
            [exit_code[0].expr(), exit_code[1].expr()]
        };

        let ecall_cfg = EcallInstructionConfig::construct_circuit(
            cb,
            [ECALL_HALT_OPCODE[0].into(), ECALL_HALT_OPCODE[1].into()],
            None,
            Some(EXIT_PC.into()),
        )?;

        // read exit_code from arg0 (X10 register)
        let (_, lt_x10_cfg) = cb.register_read(
            || "read x10",
            E::BaseField::from_canonical_u64(ceno_emul::Platform::reg_arg0() as u64),
            prev_x10_ts.expr(),
            ecall_cfg.ts.expr() + Tracer::SUBCYCLE_RS2,
            exit_code,
        )?;

        Ok(HaltConfig {
            ecall_cfg,
            prev_x10_ts,
            lt_x10_cfg,
        })
    }

    fn assign_instance(
        config: &Self::InstructionConfig,
        shard_ctx: &mut ShardContext,
        instance: &mut [E::BaseField],
        lk_multiplicity: &mut LkMultiplicity,
        step: &StepRecord,
    ) -> Result<(), ZKVMError> {
        assert_eq!(
            step.rs1().unwrap().value,
            (ECALL_HALT_OPCODE[0] + (ECALL_HALT_OPCODE[1] << 16)) as u32
        );
        assert_eq!(
            step.pc().after.0,
            0,
            "pc after ecall/halt {:x}",
            step.pc().after.0
        );

        let current_shard_offset_cycle = shard_ctx.current_shard_offset_cycle();
        let shard_cycle = step.cycle() - current_shard_offset_cycle;
        let rs2_prev_cycle = shard_ctx.aligned_prev_ts(step.rs2().unwrap().previous_cycle);
        // the access of X10 register is stored in rs2()
        set_val!(instance, config.prev_x10_ts, rs2_prev_cycle);

        shard_ctx.send(
            RAMType::Register,
            step.rs2().unwrap().addr,
            ceno_emul::Platform::reg_arg0() as u64,
            step.cycle() + Tracer::SUBCYCLE_RS2,
            step.rs2().unwrap().previous_cycle,
            step.rs2().unwrap().value,
            None,
        );

        config.lt_x10_cfg.assign_instance(
            instance,
            lk_multiplicity,
            rs2_prev_cycle,
            shard_cycle + Tracer::SUBCYCLE_RS2,
        )?;

        config
            .ecall_cfg
            .assign_instance::<E>(instance, shard_ctx, lk_multiplicity, step)?;

        Ok(())
    }
}
