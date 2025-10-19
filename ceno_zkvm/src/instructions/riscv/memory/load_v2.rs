use crate::{
    Value,
    circuit_builder::CircuitBuilder,
    error::ZKVMError,
    gadgets::SignedExtendConfig,
    instructions::{
        Instruction,
        riscv::{
            RIVInstruction,
            constants::{MEM_BITS, UInt},
            im_insn::IMInstructionConfig,
            insn_base::MemAddr,
        },
    },
    structs::ProgramParams,
    tables::InsnRecord,
    witness::{LkMultiplicity, set_val},
};
use ceno_emul::{ByteAddr, InsnKind, StepRecord};
use ff_ext::{ExtensionField, FieldInto};
use itertools::izip;
use multilinear_extensions::{Expression, ToExpr, WitIn};
use p3::field::{Field, FieldAlgebra};
use std::marker::PhantomData;

pub struct LoadConfig<E: ExtensionField> {
    im_insn: IMInstructionConfig<E>,

    rs1_read: UInt<E>,
    imm: WitIn,
    imm_sign: WitIn,
    memory_addr: MemAddr<E>,

    memory_read: UInt<E>,
    target_limb: Option<WitIn>,
    target_limb_bytes: Option<Vec<WitIn>>,
    signed_extend_config: Option<SignedExtendConfig<E>>,
}

#[derive(Default)]
pub struct LoadInstruction<E, I: Default>(PhantomData<(E, I)>);

impl<E: ExtensionField, I: RIVInstruction> Instruction<E> for LoadInstruction<E, I> {
    type InstructionConfig = LoadConfig<E>;
    type Record = StepRecord;

    fn name() -> String {
        format!("{:?}", I::INST_KIND)
    }

    fn construct_circuit(
        &self,
        circuit_builder: &mut CircuitBuilder<E>,
        _params: &ProgramParams,
    ) -> Result<Self::InstructionConfig, ZKVMError> {
        let rs1_read = UInt::new_unchecked(|| "rs1_read", circuit_builder)?; // unsigned 32-bit value
        let imm = circuit_builder.create_witin(|| "imm"); // signed 16-bit value
        let imm_sign = circuit_builder.create_witin(|| "imm_sign");

        // skip read range check, assuming constraint in write.
        let memory_read = UInt::new_unchecked(|| "memory_read", circuit_builder)?;

        let memory_addr = match I::INST_KIND {
            InsnKind::LW => MemAddr::construct_with_max_bits(circuit_builder, 2, MEM_BITS),
            InsnKind::LH | InsnKind::LHU => {
                MemAddr::construct_with_max_bits(circuit_builder, 1, MEM_BITS)
            }
            InsnKind::LB | InsnKind::LBU => {
                MemAddr::construct_with_max_bits(circuit_builder, 0, MEM_BITS)
            }
            _ => unreachable!("Unsupported instruction kind {:?}", I::INST_KIND),
        }?;

        // rs1 + imm = mem_addr
        let inv = E::BaseField::from_canonical_u32(1 << UInt::<E>::LIMB_BITS).inverse();

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

        let addr_low_bits = memory_addr.low_bit_exprs();
        let memory_value = memory_read.expr();

        // get target limb from memory word for load instructions except LW
        let target_limb = match I::INST_KIND {
            InsnKind::LB | InsnKind::LBU | InsnKind::LH | InsnKind::LHU => {
                let target_limb = circuit_builder.create_witin(|| "target_limb");
                circuit_builder.condition_require_equal(
                    || "target_limb = memory_value[low_bits[1]]",
                    addr_low_bits[1].clone(),
                    target_limb.expr(),
                    memory_value[1].clone(),
                    memory_value[0].clone(),
                )?;
                Some(target_limb)
            }
            _ => None,
        };

        // get target byte from memory word for LB and LBU
        let (target_byte_expr, target_limb_bytes) = match I::INST_KIND {
            InsnKind::LB | InsnKind::LBU => {
                let target_byte = circuit_builder.create_u8(|| "limb.le_bytes[low_bits[0]]")?;
                let dummy_byte = circuit_builder.create_u8(|| "limb.le_bytes[1-low_bits[0]]")?;

                circuit_builder.condition_require_equal(
                    || "target_byte = target_limb[low_bits[0]]",
                    addr_low_bits[0].clone(),
                    target_limb.unwrap().expr(),
                    target_byte.expr() * (1<<8) + dummy_byte.expr(), // target_byte = limb.le_bytes[1]
                    dummy_byte.expr() * (1<<8) + target_byte.expr(), // target_byte = limb.le_bytes[0]
                )?;

                (
                    Some(target_byte.expr()),
                    Some(vec![target_byte, dummy_byte]),
                )
            }
            _ => (None, None),
        };
        let (signed_extend_config, rd_written) = match I::INST_KIND {
            InsnKind::LW => (None, memory_read.clone()),
            InsnKind::LH => {
                let val = target_limb.unwrap();
                let signed_extend_config =
                    SignedExtendConfig::construct_limb(circuit_builder, val.expr())?;
                let rd_written = signed_extend_config.signed_extended_value(val.expr());

                (Some(signed_extend_config), rd_written)
            }
            InsnKind::LHU => {
                (
                    None,
                    // it's safe to unwrap as `UInt::from_exprs_unchecked` never return error
                    UInt::from_exprs_unchecked(vec![
                        target_limb.as_ref().map(|limb| limb.expr()).unwrap(),
                        Expression::ZERO,
                    ]),
                )
            }
            InsnKind::LB => {
                let val = target_byte_expr.unwrap();
                let signed_extend_config =
                    SignedExtendConfig::construct_byte(circuit_builder, val.clone())?;
                let rd_written = signed_extend_config.signed_extended_value(val);

                (Some(signed_extend_config), rd_written)
            }
            InsnKind::LBU => (
                None,
                UInt::from_exprs_unchecked(vec![target_byte_expr.unwrap(), Expression::ZERO]),
            ),
            _ => unreachable!("Unsupported instruction kind {:?}", I::INST_KIND),
        };

        let im_insn = IMInstructionConfig::<E>::construct_circuit(
            circuit_builder,
            I::INST_KIND,
            &imm.expr(),
            &imm_sign.expr(),
            rs1_read.register_expr(),
            memory_read.memory_expr(),
            memory_addr.expr_align4(),
            rd_written.register_expr(),
        )?;

        Ok(LoadConfig {
            im_insn,
            rs1_read,
            imm,
            imm_sign,
            memory_addr,
            memory_read,
            target_limb,
            target_limb_bytes,
            signed_extend_config,
        })
    }

    fn assign_instance(
        config: &Self::InstructionConfig,
        instance: &mut [E::BaseField],
        lk_multiplicity: &mut LkMultiplicity,
        step: &StepRecord,
    ) -> Result<(), ZKVMError> {
        let rs1 = Value::new_unchecked(step.rs1().unwrap().value);
        let memory_value = step.memory_op().unwrap().value.before;
        let memory_read = Value::new_unchecked(memory_value);
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
        let shift = unaligned_addr.shift();
        let addr_low_bits = [shift & 0x01, (shift >> 1) & 0x01];
        let target_limb = memory_read.as_u16_limbs()[addr_low_bits[1] as usize];
        let mut target_limb_bytes = target_limb.to_le_bytes();

        set_val!(instance, config.imm, imm.1);
        config
            .im_insn
            .assign_instance(instance, lk_multiplicity, step)?;
        config.rs1_read.assign_value(instance, rs1);
        config.memory_read.assign_value(instance, memory_read);
        config
            .memory_addr
            .assign_instance(instance, lk_multiplicity, unaligned_addr.into())?;
        if let Some(&limb) = config.target_limb.as_ref() {
            set_val!(
                instance,
                limb,
                E::BaseField::from_canonical_u16(target_limb)
            );
        }
        if let Some(limb_bytes) = config.target_limb_bytes.as_ref() {
            if addr_low_bits[0] == 1 {
                // target_limb_bytes[0] = target_limb.to_le_bytes[1]
                // target_limb_bytes[1] = target_limb.to_le_bytes[0]
                target_limb_bytes.reverse();
            }
            for (&col, byte) in izip!(limb_bytes.iter(), target_limb_bytes.into_iter()) {
                lk_multiplicity.assert_ux::<8>(byte as u64);
                set_val!(instance, col, E::BaseField::from_canonical_u8(byte));
            }
        }
        let val = match I::INST_KIND {
            InsnKind::LB | InsnKind::LBU => target_limb_bytes[0] as u64,
            InsnKind::LH | InsnKind::LHU => target_limb as u64,
            _ => 0,
        };
        if let Some(signed_ext_config) = config.signed_extend_config.as_ref() {
            signed_ext_config.assign_instance(instance, lk_multiplicity, val)?;
        }

        Ok(())
    }
}
