use ff_ext::ExtensionField;
use std::marker::PhantomData;

use crate::{
    Value,
    chip_handler::general::InstFetch,
    circuit_builder::CircuitBuilder,
    e2e::ShardContext,
    error::ZKVMError,
    instructions::{
        Instruction,
        riscv::{
            constants::{PC_BITS, UINT_LIMBS, UInt},
            i_insn::IInstructionConfig,
            insn_base::{MemAddr, ReadRS1, StateInOut, WriteRD},
        },
    },
    structs::ProgramParams,
    tables::InsnRecord,
    utils::imm_sign_extend,
    witness::{LkMultiplicity, set_val},
};
use ceno_emul::{InsnKind, PC_STEP_SIZE, StepRecord};
use ff_ext::FieldInto;
use multilinear_extensions::{Expression, ToExpr, WitIn};
use p3::field::{Field, FieldAlgebra};

pub struct JalrConfig<E: ExtensionField> {
    pub i_insn: IInstructionConfig<E>,
    pub rs1_read: UInt<E>,
    pub imm: WitIn,
    pub imm_sign: WitIn,
    pub jump_pc_addr: MemAddr<E>,
    pub rd_high: WitIn,
}

#[derive(Default)]
pub struct JalrInstruction<E>(PhantomData<E>);

/// JALR instruction circuit
/// NOTE: does not validate that next_pc is aligned by 4-byte increments, which
///   should be verified by lookup argument of the next execution step against
///   the program table
impl<E: ExtensionField> Instruction<E> for JalrInstruction<E> {
    type InstructionConfig = JalrConfig<E>;
    type Record = StepRecord;

    fn name() -> String {
        format!("{:?}", InsnKind::JALR)
    }

    fn construct_circuit(
        &self,
        circuit_builder: &mut CircuitBuilder<E>,
        _params: &ProgramParams,
    ) -> Result<JalrConfig<E>, ZKVMError> {
        assert_eq!(UINT_LIMBS, 2);
        let rs1_read = UInt::new_unchecked(|| "rs1_read", circuit_builder)?; // unsigned 32-bit value
        let imm = circuit_builder.create_witin(|| "imm"); // signed 12-bit value
        let imm_sign = circuit_builder.create_witin(|| "imm_sign");
        // State in and out
        let vm_state = StateInOut::construct_circuit(circuit_builder, true)?;
        let rd_high = circuit_builder.create_witin(|| "rd_high");
        let rd_low: Expression<_> = vm_state.pc.expr()
            + E::BaseField::from_canonical_usize(PC_STEP_SIZE).expr()
            - rd_high.expr() * E::BaseField::from_canonical_u32(1 << UInt::<E>::LIMB_BITS).expr();
        // rd range check
        // rd_low
        circuit_builder.assert_const_range(|| "rd_low_u16", rd_low.expr(), UInt::<E>::LIMB_BITS)?;
        // rd_high
        circuit_builder.assert_const_range(
            || "rd_high_range",
            rd_high.expr(),
            PC_BITS - UInt::<E>::LIMB_BITS,
        )?;
        let rd_uint = UInt::from_exprs_unchecked(vec![rd_low.expr(), rd_high.expr()]);

        let jump_pc_addr = MemAddr::construct_with_max_bits(circuit_builder, 0, PC_BITS)?;

        // Registers
        let rs1 =
            ReadRS1::construct_circuit(circuit_builder, rs1_read.register_expr(), vm_state.ts)?;
        let rd = WriteRD::construct_circuit(circuit_builder, rd_uint.register_expr(), vm_state.ts)?;

        // Fetch the instruction.
        circuit_builder.lk_fetch(&InsnRecord::new(
            vm_state.pc.expr(),
            InsnKind::JALR.into(),
            Some(rd.id.expr()),
            rs1.id.expr(),
            0.into(),
            imm.expr(),
            imm_sign.expr(),
        ))?;

        let i_insn = IInstructionConfig { vm_state, rs1, rd };

        // Next pc is obtained by rounding rs1+imm down to an even value.
        // To implement this, check three conditions:
        //  1. rs1 + imm = jump_pc_addr + overflow*2^32
        //  3. next_pc = jump_pc_addr aligned to even value (round down)

        let inv = E::BaseField::from_canonical_u32(1 << UInt::<E>::LIMB_BITS).inverse();

        let carry = (rs1_read.expr()[0].expr() + imm.expr()
            - jump_pc_addr.uint_unaligned().expr()[0].expr())
            * inv.expr();
        circuit_builder.assert_bit(|| "carry_lo_bit", carry.expr())?;

        let imm_extend_limb = imm_sign.expr()
            * E::BaseField::from_canonical_u32((1 << UInt::<E>::LIMB_BITS) - 1).expr();
        let carry = (rs1_read.expr()[1].expr() + imm_extend_limb.expr() + carry
            - jump_pc_addr.uint_unaligned().expr()[1].expr())
            * inv.expr();
        circuit_builder.assert_bit(|| "overflow_bit", carry)?;

        circuit_builder.require_equal(
            || "jump_pc_addr = next_pc",
            jump_pc_addr.expr_align2(),
            i_insn.vm_state.next_pc.unwrap().expr(),
        )?;

        // write pc+4 to rd
        circuit_builder.require_equal(
            || "rd_written = pc+4",
            rd_uint.value(), // this operation is safe
            i_insn.vm_state.pc.expr() + PC_STEP_SIZE,
        )?;

        Ok(JalrConfig {
            i_insn,
            rs1_read,
            imm,
            imm_sign,
            jump_pc_addr,
            rd_high,
        })
    }

    fn assign_instance(
        config: &Self::InstructionConfig,
        shard_ctx: &mut ShardContext,
        instance: &mut [E::BaseField],
        lk_multiplicity: &mut LkMultiplicity,
        step: &ceno_emul::StepRecord,
    ) -> Result<(), ZKVMError> {
        let insn = step.insn();

        let rs1 = step.rs1().unwrap().value;
        let imm = InsnRecord::<E::BaseField>::imm_internal(&insn);
        set_val!(instance, config.imm, imm.1);
        // according to riscvim32 spec, imm always do signed extension
        let imm_sign_extend = imm_sign_extend(true, step.insn().imm as i16);
        set_val!(
            instance,
            config.imm_sign,
            E::BaseField::from_bool(imm_sign_extend[1] > 0)
        );
        let rd = Value::new_unchecked(step.rd().unwrap().value.after);
        let rd_limb = rd.as_u16_limbs();
        lk_multiplicity.assert_const_range(rd_limb[0] as u64, 16);
        lk_multiplicity.assert_const_range(rd_limb[1] as u64, PC_BITS - 16);

        config
            .rs1_read
            .assign_value(instance, Value::new_unchecked(rs1));
        set_val!(
            instance,
            config.rd_high,
            E::BaseField::from_canonical_u16(rd_limb[1])
        );

        let (sum, _) = rs1.overflowing_add_signed(i32::from_ne_bytes([
            imm_sign_extend[0] as u8,
            (imm_sign_extend[0] >> 8) as u8,
            imm_sign_extend[1] as u8,
            (imm_sign_extend[1] >> 8) as u8,
        ]));
        config
            .jump_pc_addr
            .assign_instance(instance, lk_multiplicity, sum)?;

        config
            .i_insn
            .assign_instance(instance, shard_ctx, lk_multiplicity, step)?;

        Ok(())
    }
}
