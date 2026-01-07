use crate::{
    Value,
    chip_handler::general::InstFetch,
    circuit_builder::CircuitBuilder,
    e2e::ShardContext,
    error::ZKVMError,
    instructions::{
        Instruction,
        riscv::{
            RIVInstruction,
            constants::{MEM_BITS, UInt},
            insn_base::{MemAddr, RWMEM, ReadRS1, ReadRS2, StateInOut, WriteRD},
        },
    },
    structs::ProgramParams,
    tables::InsnRecord,
    witness::LkMultiplicity,
};
use ceno_emul::{
    ByteAddr,
    InsnKind::{LW, SW},
    StepRecord,
};
use either::Either;
use ff_ext::{ExtensionField, FieldInto};
use multilinear_extensions::{Expression, ToExpr, WitIn};
use p3::field::{Field, FieldAlgebra};
use std::marker::PhantomData;
use witness::set_val;

pub struct LoadStoreWordConfig<E: ExtensionField> {
    is_load: WitIn,
    vm_state: StateInOut<E>,

    rs1_read: UInt<E>,
    rs1: ReadRS1<E>,
    imm: WitIn,
    imm_sign: WitIn,
    memory_addr: MemAddr<E>,

    // for load
    rd_written: WriteRD<E>,

    // for store
    rs2_read: UInt<E>,
    rs2: ReadRS2<E>,
    prev_memory_value: UInt<E>,
    mem_rw: RWMEM,
}

pub struct LoadStoreWordInstruction<E, I>(PhantomData<(E, I)>);
impl<E: ExtensionField, I: RIVInstruction> Instruction<E> for LoadStoreWordInstruction<E, I> {
    type InstructionConfig = LoadStoreWordConfig<E>;

    fn name() -> String {
        format!("{:?}", I::INST_KIND)
    }

    fn construct_circuit(
        circuit_builder: &mut CircuitBuilder<E>,
        _params: &ProgramParams,
    ) -> Result<Self::InstructionConfig, ZKVMError> {
        let rs1_read = UInt::new_unchecked(|| "rs1_read", circuit_builder)?; // unsigned 32-bit value
        let rs2_read = UInt::new_unchecked(|| "rs2_read", circuit_builder)?;
        let imm = circuit_builder.create_witin(|| "imm"); // signed 16-bit value
        let imm_sign = circuit_builder.create_witin(|| "imm_sign");

        let is_load = circuit_builder.create_bit(|| "is_load")?;
        let is_store = Expression::ONE - is_load.expr();

        // skip read range check, assuming constraint in write.
        let prev_memory_value = UInt::new_unchecked(|| "prev_memory_value", circuit_builder)?;
        let memory_addr = MemAddr::construct_with_max_bits(circuit_builder, 2, MEM_BITS)?;

        // rs1 + imm = memory_addr
        let inv = E::BaseField::from_canonical_u32(1 << UInt::<E>::LIMB_BITS).inverse();

        // constrain memory_addr
        let carry = (rs1_read.expr()[0].expr() + imm.expr()
            - memory_addr.uint_unaligned().expr()[0].expr())
            * inv.expr();
        circuit_builder.assert_bit(|| "carry_lo_bit", carry.expr())?;

        let imm_extend_limb = imm_sign.expr()
            * E::BaseField::from_canonical_u32((1 << UInt::<E>::LIMB_BITS) - 1).expr();
        let carry = (rs1_read.expr()[1].expr() + imm_extend_limb.expr() + carry
            - memory_addr.uint_unaligned().expr()[1].expr())
            * inv.expr();
        circuit_builder.assert_bit(|| "overflow_bit", carry)?;

        // state in and out
        let vm_state = StateInOut::construct_circuit(circuit_builder, false)?;

        // reg read
        let rs1 =
            ReadRS1::construct_circuit(circuit_builder, rs1_read.register_expr(), vm_state.ts)?;
        let rs2 = ReadRS2::construct_conditional_circuit(
            circuit_builder,
            is_store.expr(),
            rs2_read.register_expr(),
            vm_state.ts,
        )?;

        // rd written
        let rd_written = WriteRD::construct_conditional_circuit(
            circuit_builder,
            is_load.expr(),
            prev_memory_value.memory_expr(),
            vm_state.ts,
        )?;

        let insn_kind: Expression<E> = is_load.expr()
            * Expression::Constant(Either::Left(E::BaseField::from_canonical_u32(LW as u32)))
            + is_store.expr()
                * Expression::Constant(Either::Left(E::BaseField::from_canonical_u32(SW as u32)));

        // Fetch instruction
        circuit_builder.lk_fetch(&InsnRecord::new(
            vm_state.pc.expr(),
            insn_kind,
            None,
            rs1.id.expr(),
            rs2.id.expr(),
            imm.expr(),
            #[cfg(feature = "u16limb_circuit")]
            imm_sign.expr(),
        ))?;

        // Memory
        let mem_rw = RWMEM::construct_circuit(
            circuit_builder,
            is_load.expr(),
            memory_addr.expr_align4(),
            prev_memory_value.memory_expr(),
            rs2_read.memory_expr(),
            vm_state.ts,
        )?;

        Ok(LoadStoreWordConfig {
            is_load,
            vm_state,
            rs1_read,
            rs1,
            rs2_read,
            rs2,
            rd_written,
            imm,
            imm_sign,
            memory_addr,
            prev_memory_value,
            mem_rw,
        })
    }

    fn assign_instance(
        config: &Self::InstructionConfig,
        shard_ctx: &mut ShardContext,
        instance: &mut [E::BaseField],
        lk_multiplicity: &mut LkMultiplicity,
        step: &StepRecord,
    ) -> Result<(), ZKVMError> {
        match step.insn.kind {
            LW => {
                set_val!(instance, config.is_load, 1u64);
                let rs1 = Value::new_unchecked(step.rs1().unwrap().value);
                let prev_memory_value = step.memory_op().unwrap().value.before;
                let prev_memory_read = Value::new_unchecked(prev_memory_value);
                // imm is signed 16-bit value
                let imm = InsnRecord::<E::BaseField>::imm_internal(&step.insn());
                let imm_sign_extend = crate::utils::imm_sign_extend(true, step.insn().imm as i16);
                set_val!(
                    instance,
                    config.imm_sign,
                    E::BaseField::from_bool(imm_sign_extend[1] > 0)
                );
                let unaligned_addr =
                    ByteAddr::from(step.rs1().unwrap().value.wrapping_add_signed(imm.0 as i32));

                set_val!(instance, config.imm, imm.1);

                config.vm_state.assign_instance(instance, shard_ctx, step)?;
                config
                    .rs1
                    .assign_instance(instance, shard_ctx, lk_multiplicity, step)?;
                config
                    .rd_written
                    .assign_instance(instance, shard_ctx, lk_multiplicity, step)?;
                config
                    .mem_rw
                    .assign_instance::<E>(instance, shard_ctx, lk_multiplicity, step)?;

                // Fetch instruction
                lk_multiplicity.fetch(step.pc().before.0);

                config.rs1_read.assign_value(instance, rs1);
                config
                    .prev_memory_value
                    .assign_value(instance, prev_memory_read);
                config.memory_addr.assign_instance(
                    instance,
                    lk_multiplicity,
                    unaligned_addr.into(),
                )?;
            }
            SW => {
                set_val!(instance, config.is_load, 0u64);
                let rs1 = Value::new_unchecked(step.rs1().unwrap().value);
                let rs2 = Value::new_unchecked(step.rs2().unwrap().value);
                let memory_op = step.memory_op().unwrap();
                // imm is signed 16-bit value
                let imm = InsnRecord::<E::BaseField>::imm_internal(&step.insn());
                let imm_sign_extend = crate::utils::imm_sign_extend(true, step.insn().imm as i16);
                set_val!(
                    instance,
                    config.imm_sign,
                    E::BaseField::from_bool(imm_sign_extend[1] > 0)
                );
                let prev_mem_value = Value::new_unchecked(memory_op.value.before);

                let addr =
                    ByteAddr::from(step.rs1().unwrap().value.wrapping_add_signed(imm.0 as i32));
                config.vm_state.assign_instance(instance, shard_ctx, step)?;
                config
                    .rs1
                    .assign_instance(instance, shard_ctx, lk_multiplicity, step)?;
                config
                    .rs2
                    .assign_instance(instance, shard_ctx, lk_multiplicity, step)?;
                config
                    .mem_rw
                    .assign_instance::<E>(instance, shard_ctx, lk_multiplicity, step)?;

                // Fetch instruction
                lk_multiplicity.fetch(step.pc().before.0);
                config.rs1_read.assign_value(instance, rs1);
                config.rs2_read.assign_value(instance, rs2);
                set_val!(instance, config.imm, imm.1);
                config
                    .prev_memory_value
                    .assign_value(instance, prev_mem_value);
                config
                    .memory_addr
                    .assign_instance(instance, lk_multiplicity, addr.into())?;
            }
            _ => unreachable!(),
        }
        Ok(())
    }
}
