// will remove #[allow(dead_code)] when we finished fibonacci integration test
use crate::{
    Value,
    circuit_builder::CircuitBuilder,
    error::ZKVMError,
    expression::{Expression, ToExpr, WitIn},
    instructions::{
        Instruction,
        riscv::{
            RIVInstruction, constants::UInt, im_insn::IMInstructionConfig, insn_base::MemAddr,
            memory::gadget::SignedExtConfig,
        },
    },
    set_val,
    tables::InsnRecord,
    uint::UintLimb,
    witness::LkMultiplicity,
};
use ceno_emul::{ByteAddr, InsnKind, StepRecord};
use ff_ext::ExtensionField;
use itertools::izip;
use std::{marker::PhantomData, mem::MaybeUninit};

pub struct LoadConfig<E: ExtensionField> {
    im_insn: IMInstructionConfig<E>,

    rs1_read: UInt<E>,
    imm: WitIn,
    memory_addr: MemAddr<E>,

    memory_read: UInt<E>,
    target_limb: Option<WitIn>,
    target_limb_bytes: Option<Vec<WitIn>>,
    sext_config: Option<SignedExtConfig>,
}

pub struct LoadInstruction<E, I>(PhantomData<(E, I)>);

pub struct LwOp;

impl RIVInstruction for LwOp {
    const INST_KIND: InsnKind = InsnKind::LW;
}

pub type LwInstruction<E> = LoadInstruction<E, LwOp>;

pub struct LhOp;
impl RIVInstruction for LhOp {
    const INST_KIND: InsnKind = InsnKind::LH;
}
#[allow(dead_code)]
pub type LhInstruction<E> = LoadInstruction<E, LhOp>;

pub struct LhuOp;
impl RIVInstruction for LhuOp {
    const INST_KIND: InsnKind = InsnKind::LHU;
}
#[allow(dead_code)]
pub type LhuInstruction<E> = LoadInstruction<E, LhuOp>;

pub struct LbOp;
impl RIVInstruction for LbOp {
    const INST_KIND: InsnKind = InsnKind::LB;
}
#[allow(dead_code)]
pub type LbInstruction<E> = LoadInstruction<E, LbOp>;

pub struct LbuOp;
impl RIVInstruction for LbuOp {
    const INST_KIND: InsnKind = InsnKind::LBU;
}
#[allow(dead_code)]
pub type LbuInstruction<E> = LoadInstruction<E, LbuOp>;

impl<E: ExtensionField, I: RIVInstruction> Instruction<E> for LoadInstruction<E, I> {
    type InstructionConfig = LoadConfig<E>;

    fn name() -> String {
        format!("{:?}", I::INST_KIND)
    }

    fn construct_circuit(
        circuit_builder: &mut CircuitBuilder<E>,
    ) -> Result<Self::InstructionConfig, ZKVMError> {
        let rs1_read = UInt::new_unchecked(|| "rs1_read", circuit_builder)?; // unsigned 32-bit value
        let imm = circuit_builder.create_witin(|| "imm")?; // signed 12-bit value
        let memory_read = UInt::new(|| "memory_read", circuit_builder)?;

        let memory_addr = match I::INST_KIND {
            InsnKind::LW => MemAddr::construct_align4(circuit_builder),
            InsnKind::LH | InsnKind::LHU => MemAddr::construct_align2(circuit_builder),
            InsnKind::LB | InsnKind::LBU => MemAddr::construct_unaligned(circuit_builder),
            _ => unreachable!("Unsupported instruction kind {:?}", I::INST_KIND),
        }?;

        circuit_builder.require_equal(
            || "memory_addr = rs1_read + imm",
            memory_addr.expr_unaligned(),
            rs1_read.value() + imm.expr(),
        )?;

        let addr_low_bits = memory_addr.low_bit_exprs();
        let memory_value = memory_read.expr();

        // get target limb from memory word for load instructions except LW
        let target_limb = if I::INST_KIND != InsnKind::LW {
            let target_limb = circuit_builder.create_u16(|| "target_limb")?;
            circuit_builder.condition_require_equal(
                || "target_limb = memory_value[low_bits[1]]",
                addr_low_bits[1].clone(),
                target_limb.expr(),
                memory_value[1].clone(),
                memory_value[0].clone(),
            )?;
            Some(target_limb)
        } else {
            None
        };

        // get target byte from memory word for LB and LBU
        let target_limb_bytes = match I::INST_KIND {
            InsnKind::LB | InsnKind::LBU => {
                let target_byte = circuit_builder.create_u8(|| "limb.le_bytes[low_bits[0]]")?;
                let sibling_byte = circuit_builder.create_u8(|| "limb.le_bytes[!low_bits[0]]")?;

                circuit_builder.condition_require_equal(
                    || "target_byte = target_limb[low_bits[0]]",
                    addr_low_bits[0].clone(),
                    target_limb.unwrap().expr(),
                    target_byte.expr() * (1<<8) + sibling_byte.expr(), // target_byte = limb.le_bytes[1]
                    sibling_byte.expr() * (1<<8) + target_byte.expr(), // target_byte = limb.le_bytes[0]
                )?;

                Some(vec![target_byte, sibling_byte])
            }
            _ => None,
        };
        let (sext_config, rd_written) = match I::INST_KIND {
            InsnKind::LW => (None, memory_read.clone()),
            InsnKind::LH => {
                let val = target_limb.unwrap();
                let sext_config = SignedExtConfig::construct_limb(circuit_builder, val.expr())?;
                let rd_written = sext_config.sext_value(val.expr());

                (Some(sext_config), rd_written)
            }
            InsnKind::LHU => {
                let mut rd_written = UInt::new_as_empty();
                rd_written.limbs =
                    UintLimb::Expression(vec![Expression::ZERO, target_limb.unwrap().expr()]);

                (None, rd_written)
            }
            InsnKind::LB => {
                let val = target_limb_bytes.clone().unwrap()[0];
                let sext_config = SignedExtConfig::construct_byte(circuit_builder, val.expr())?;
                let rd_written = sext_config.sext_value(val.expr());

                (Some(sext_config), rd_written)
            }
            InsnKind::LBU => {
                let mut rd_written = UInt::new_as_empty();
                rd_written.limbs = UintLimb::Expression(vec![
                    Expression::ZERO,
                    target_limb_bytes.clone().unwrap()[0].expr(),
                ]);

                (None, rd_written)
            }
            _ => unreachable!("Unsupported instruction kind {:?}", I::INST_KIND),
        };

        let im_insn = IMInstructionConfig::<E>::construct_circuit(
            circuit_builder,
            I::INST_KIND,
            &imm.expr(),
            rs1_read.register_expr(),
            memory_read.memory_expr(),
            memory_addr.expr_align4(),
            rd_written.register_expr(),
        )?;

        Ok(LoadConfig {
            im_insn,
            rs1_read,
            imm,
            memory_addr,
            memory_read,
            target_limb,
            target_limb_bytes,
            sext_config,
        })
    }

    fn assign_instance(
        config: &Self::InstructionConfig,
        instance: &mut [MaybeUninit<E::BaseField>],
        lk_multiplicity: &mut LkMultiplicity,
        step: &StepRecord,
    ) -> Result<(), ZKVMError> {
        let rs1 = Value::new_unchecked(step.rs1().unwrap().value);
        let memory_value = step.memory_op().unwrap().value.before;
        let memory_read = Value::new(memory_value, lk_multiplicity);
        // imm is signed 12-bit value
        let imm: E::BaseField = InsnRecord::imm_or_funct7_field(&step.insn());
        let unaligned_addr = ByteAddr::from(
            step.rs1()
                .unwrap()
                .value
                .wrapping_add(step.insn().imm_or_funct7()),
        );
        let shift = unaligned_addr.shift();
        let addr_low_bits = [shift & 0x01, (shift >> 1) & 0x01];
        let target_limb = memory_read.as_u16_limbs()[addr_low_bits[1] as usize];
        let mut target_limb_bytes = target_limb.to_le_bytes();

        set_val!(instance, config.imm, imm);
        config
            .im_insn
            .assign_instance(instance, lk_multiplicity, step)?;
        config.rs1_read.assign_value(instance, rs1);
        config.memory_read.assign_value(instance, memory_read);
        config
            .memory_addr
            .assign_instance(instance, lk_multiplicity, unaligned_addr.into())?;
        if config.target_limb.is_some() {
            lk_multiplicity.assert_ux::<16>(target_limb as u64);
            set_val!(
                instance,
                config.target_limb.unwrap(),
                E::BaseField::from(target_limb as u64)
            );
        }
        if config.target_limb_bytes.is_some() {
            if addr_low_bits[0] == 1 {
                target_limb_bytes.reverse();
            }
            for (&col, byte) in izip!(
                config.target_limb_bytes.clone().unwrap().iter(),
                target_limb_bytes.into_iter().map(|byte| byte as u64)
            ) {
                lk_multiplicity.assert_ux::<8>(byte);
                set_val!(instance, col, E::BaseField::from(byte));
            }
        }
        let val = match I::INST_KIND {
            InsnKind::LB | InsnKind::LBU => target_limb_bytes[0] as u64,
            InsnKind::LH | InsnKind::LHU => target_limb as u64,
            _ => 0,
        };
        if config.sext_config.is_some() {
            let sext_config = config.sext_config.as_ref().unwrap();
            sext_config.assign_instance::<E>(instance, lk_multiplicity, val)?;
        }

        Ok(())
    }
}
