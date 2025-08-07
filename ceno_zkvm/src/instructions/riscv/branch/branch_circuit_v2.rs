use crate::{
    circuit_builder::CircuitBuilder,
    error::ZKVMError,
    gadgets::SignedLtConfig,
    instructions::{
        Instruction,
        riscv::{
            RIVInstruction,
            b_insn::BInstructionConfig,
            constants::{UINT_LIMBS, UInt},
        },
    },
    structs::ProgramParams,
    witness::LkMultiplicity,
};
use ceno_emul::{InsnKind, StepRecord};
use ff_ext::ExtensionField;
use gkr_iop::gadgets::{IsEqualConfig, IsLtConfig};
use multilinear_extensions::{Expression, ToExpr, WitIn};
use std::{array, marker::PhantomData};

pub struct BranchCircuit<E, I>(PhantomData<(E, I)>);

pub struct BranchConfig<E: ExtensionField> {
    pub b_insn: BInstructionConfig<E>,
    pub read_rs1: UInt<E>,
    pub read_rs2: UInt<E>,

    // Most significant limb of a and b respectively as a field element, will be range
    // checked to be within [-128, 127) if signed and [0, 256) if unsigned.
    pub read_rs1_msb_f: WitIn,
    pub read_rs2_msb_f: WitIn,

    // 1 at the most significant index i such that read_rs1[i] != read_rs2[i], otherwise 0. If such
    // an i exists, diff_val = read_rs2[i] - read_rs1[i].
    pub diff_marker: [WitIn; UINT_LIMBS],
    pub diff_val: WitIn,
    phantom: PhantomData<E>,
}

impl<E: ExtensionField, I: RIVInstruction> Instruction<E> for BranchCircuit<E, I> {
    type InstructionConfig = BranchConfig<E>;

    fn name() -> String {
        todo!()
    }

    fn construct_circuit(
        circuit_builder: &mut CircuitBuilder<E>,
        param: &ProgramParams,
    ) -> Result<Self::InstructionConfig, ZKVMError> {
        let read_rs1 = UInt::new_unchecked(|| "rs1_limbs", circuit_builder)?;
        let read_rs2 = UInt::new_unchecked(|| "rs2_limbs", circuit_builder)?;

        let read_rs1_expr = read_rs1.expr();
        let read_rs2_expr = read_rs2.expr();

        let read_rs1_msb_f = circuit_builder.create_witin(|| "read_rs1_msb_f");
        let read_rs2_msb_f = circuit_builder.create_witin(|| "read_rs2_msb_f");
        let diff_marker: [WitIn; UINT_LIMBS] =
            array::from_fn(|_| circuit_builder.create_witin(|| "diff_maker"));
        let diff_val = circuit_builder.create_witin(|| "diff_val");

        // Check if a_msb_f and b_msb_f are signed values of read_rs1[NUM_LIMBS - 1] and read_rs2[NUM_LIMBS - 1] in prime field F.
        let a_diff = read_rs1_expr[UINT_LIMBS - 1].expr() - read_rs1_msb_f.expr();
        let b_diff = read_rs2_expr[UINT_LIMBS - 1].expr() - read_rs2_msb_f.expr();

        let (branch_taken_bit, is_equal, is_signed_lt, is_unsigned_lt) = match I::INST_KIND {
            InsnKind::BEQ => {
                let equal = IsEqualConfig::construct_circuit(
                    circuit_builder,
                    || "rs1!=rs2",
                    read_rs2.value(),
                    read_rs1.value(),
                )?;
                (equal.expr(), Some(equal), None, None)
            }
            InsnKind::BNE => {
                let equal = IsEqualConfig::construct_circuit(
                    circuit_builder,
                    || "rs1==rs2",
                    read_rs2.value(),
                    read_rs1.value(),
                )?;
                (Expression::ONE - equal.expr(), Some(equal), None, None)
            }
            InsnKind::BLT => {
                let signed_lt = SignedLtConfig::construct_circuit(
                    circuit_builder,
                    || "rs1<rs2",
                    &read_rs1,
                    &read_rs2,
                )?;
                (signed_lt.expr(), None, Some(signed_lt), None)
            }
            InsnKind::BGE => {
                let signed_lt = SignedLtConfig::construct_circuit(
                    circuit_builder,
                    || "rs1>=rs2",
                    &read_rs1,
                    &read_rs2,
                )?;
                (
                    Expression::ONE - signed_lt.expr(),
                    None,
                    Some(signed_lt),
                    None,
                )
            }
            InsnKind::BLTU => {
                let unsigned_lt = IsLtConfig::construct_circuit(
                    circuit_builder,
                    || "rs1<rs2",
                    read_rs1.value(),
                    read_rs2.value(),
                    UINT_LIMBS,
                )?;
                (unsigned_lt.expr(), None, None, Some(unsigned_lt))
            }
            InsnKind::BGEU => {
                let unsigned_lt = IsLtConfig::construct_circuit(
                    circuit_builder,
                    || "rs1 >= rs2",
                    read_rs1.value(),
                    read_rs2.value(),
                    UINT_LIMBS,
                )?;
                (
                    Expression::ONE - unsigned_lt.expr(),
                    None,
                    None,
                    Some(unsigned_lt),
                )
            }
            _ => unreachable!("Unsupported instruction kind {:?}", I::INST_KIND),
        };

        let b_insn = BInstructionConfig::construct_circuit(
            circuit_builder,
            I::INST_KIND,
            read_rs1.register_expr(),
            read_rs2.register_expr(),
            branch_taken_bit,
        )?;

        // Ok(BranchConfig {
        //     b_insn,
        //     read_rs1,
        //     read_rs2,
        //     ..
        // })
        todo!()
    }

    fn assign_instance(
        _config: &Self::InstructionConfig,
        _instance: &mut [E::BaseField],
        _lk_multiplicity: &mut LkMultiplicity,
        _step: &StepRecord,
    ) -> Result<(), ZKVMError> {
        todo!()
    }
}
