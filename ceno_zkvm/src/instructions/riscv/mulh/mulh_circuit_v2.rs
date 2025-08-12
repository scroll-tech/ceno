use crate::{
    circuit_builder::CircuitBuilder,
    error::ZKVMError,
    gadgets::Signed,
    instructions::{
        Instruction,
        riscv::{
            RIVInstruction,
            constants::{UINT_LIMBS, UInt},
            r_insn::RInstructionConfig,
        },
    },
    structs::ProgramParams,
    witness::LkMultiplicity,
};
use ceno_emul::{InsnKind, StepRecord};
use ff_ext::ExtensionField;
use multilinear_extensions::{Expression, ToExpr as _, WitIn};
use p3::field::{Field, FieldAlgebra};

use std::{array, marker::PhantomData};

pub struct MulhInstructionBase<E, I>(PhantomData<(E, I)>);

pub struct MulhConfig<E: ExtensionField> {
    rd_mul: WitIn,
    phantom: PhantomData<E>,
}

impl<E: ExtensionField, I: RIVInstruction> Instruction<E> for MulhInstructionBase<E, I> {
    type InstructionConfig = MulhConfig<E>;

    fn name() -> String {
        format!("{:?}", I::INST_KIND)
    }

    fn construct_circuit(
        circuit_builder: &mut CircuitBuilder<E>,
        _params: &ProgramParams,
    ) -> Result<MulhConfig<E>, ZKVMError> {
        assert_eq!(UInt::<E>::TOTAL_BITS, u32::BITS as usize);
        assert_eq!(UInt::<E>::LIMB_BITS, 16);
        assert_eq!(UInt::<E>::NUM_LIMBS, 2);

        // 0. Registers and instruction lookup
        let rs1_read = UInt::new_unchecked(|| "rs1_read", circuit_builder)?;
        let rs2_read = UInt::new_unchecked(|| "rs2_read", circuit_builder)?;
        let rd_written = UInt::new(|| "rd_written", circuit_builder)?;

        let rs1_expr = rs1_read.expr();
        let rs2_expr = rs2_read.expr();
        let rd_expr = rd_written.expr();

        let carry_divide = E::BaseField::from_canonical_u32(1 << UInt::<E>::LIMB_BITS).inverse();

        let rd_low: [_; UINT_LIMBS] =
            array::from_fn(|i| circuit_builder.create_witin(|| format!("rd_mul_{i}")));
        let mut carry_low: [Expression<E>; UINT_LIMBS] = array::from_fn(|i| {
            circuit_builder
                .create_witin(|| format!("carry_low_{i}"))
                .expr()
        });

        for i in 0..UINT_LIMBS {
            let expected_limb = if i == 0 {
                E::BaseField::ZERO.expr()
            } else {
                carry_low[i - 1].clone()
            } + (0..=i).fold(E::BaseField::ZERO.expr(), |ac, k| {
                ac + (rs1_expr[k].clone() * rs2_expr[i - k].clone())
            });
            carry_low[i] = carry_divide.expr() * (expected_limb - rd_low[i].expr());
        }

        for (rd_low, carry_mul) in rd_low.iter().zip(carry_low.iter()) {
            circuit_builder.assert_ux::<_, _, 16>(|| "range_check_low", rd_low.expr())?;
            circuit_builder.assert_ux::<_, _, 16>(|| "range_check_carry", carry_mul.clone())?;
        }

        let mut carry_high: [Expression<E>; UINT_LIMBS] = array::from_fn(|i| {
            circuit_builder
                .create_witin(|| format!("carry_high_{i}"))
                .expr()
        });

        for j in 0..UINT_LIMBS {
            let expected_limb =
                if j == 0 {
                    carry_low[UINT_LIMBS - 1].clone()
                } else {
                    carry_high[j - 1].clone()
                } + ((j + 1)..UINT_LIMBS).fold(E::BaseField::ZERO.expr(), |acc, k| {
                    acc + (rs1_expr[k] * rs2_expr[UINT_LIMBS + j - k])
                }) + (0..(j + 1)).fold(E::BaseField::ZERO.expr(), |acc, k| {
                    acc + (rs1_expr[k] * cols.c_ext) + (rs2_expr[k] * cols.b_ext)
                });
            carry_high[j] = E::BaseField::from(carry_divide).expr() * (expected_limb - rd_expr[j]);
        }

        match I::INST_KIND {
            InsnKind::MULH => {
                // Implement MULH circuit here
            }
            InsnKind::MULHU => {
                // Implement MULHU circuit here
            }
            InsnKind::MULHSU => {
                // Implement MULHSU circuit here
            }
            InsnKind::MUL => {
                // Implement MUL circuit here
            }
            _ => unreachable!("Unsupported instruction kind"),
        }

        unimplemented!()
    }

    fn assign_instance(
        _config: &Self::InstructionConfig,
        _instance: &mut [<E as ExtensionField>::BaseField],
        _lk_multiplicity: &mut LkMultiplicity,
        _step: &StepRecord,
    ) -> Result<(), ZKVMError> {
        unimplemented!()
    }
}
