use crate::{
    Value,
    circuit_builder::CircuitBuilder,
    e2e::ShardContext,
    error::ZKVMError,
    gadgets::{UIntLimbsLT, UIntLimbsLTConfig},
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
use ff_ext::{ExtensionField, FieldInto};
use multilinear_extensions::{Expression, ToExpr, WitIn};
use p3::field::{Field, FieldAlgebra};
use std::{array, marker::PhantomData};
use witness::set_val;

pub struct BranchCircuit<E, I>(PhantomData<(E, I)>);

pub struct BranchConfig<E: ExtensionField> {
    pub b_insn: BInstructionConfig<E>,
    pub read_rs1: UInt<E>,
    pub read_rs2: UInt<E>,

    // for non eq opcode config
    pub uint_lt_config: Option<UIntLimbsLTConfig<E>>,
    // for beq/bne
    pub eq_diff_inv_marker: Option<[WitIn; UINT_LIMBS]>,
    pub eq_branch_taken_bit: Option<WitIn>,
    phantom: PhantomData<E>,
}

impl<E: ExtensionField, I: RIVInstruction> Instruction<E> for BranchCircuit<E, I> {
    type InstructionConfig = BranchConfig<E>;
    type InsnType = InsnKind;

    fn inst_kinds() -> &'static [Self::InsnType] {
        &[I::INST_KIND]
    }

    fn name() -> String {
        format!("{:?}", I::INST_KIND)
    }

    fn construct_circuit(
        circuit_builder: &mut CircuitBuilder<E>,
        _param: &ProgramParams,
    ) -> Result<Self::InstructionConfig, ZKVMError> {
        let read_rs1 = UInt::new_unchecked(|| "rs1_limbs", circuit_builder)?;
        let read_rs2 = UInt::new_unchecked(|| "rs2_limbs", circuit_builder)?;

        let (branch_taken_bit_expr, eq_branch_taken_bit, eq_diff_inv_marker, uint_lt_config) =
            if matches!(I::INST_KIND, InsnKind::BEQ | InsnKind::BNE) {
                let branch_taken_bit = circuit_builder.create_bit(|| "branch_taken_bit")?;
                let eq_diff_inv_marker = array::from_fn(|i| {
                    circuit_builder.create_witin(|| format!("eq_diff_inv_marker_{i}"))
                });

                // 1 if cmp_result indicates a and b are EQUAL, 0 otherwise
                let cmp_eq = match I::INST_KIND {
                    InsnKind::BEQ => branch_taken_bit.expr(),
                    InsnKind::BNE => Expression::ONE - branch_taken_bit.expr(),
                    _ => unreachable!(),
                };
                let mut sum = cmp_eq.expr();

                // For BEQ, inv_marker is used to check equality of a and b:
                // - If a == b, all inv_marker values must be 0 (sum = 0)
                // - If a != b, inv_marker contains 0s for all positions except ONE position i where a[i] !=
                //   b[i]
                // - At this position, inv_marker[i] contains the multiplicative inverse of (a[i] - b[i])
                // - This ensures inv_marker[i] * (a[i] - b[i]) = 1, making the sum = 1
                // Note: There might be multiple valid inv_marker if a != b.
                // But as long as the trace can provide at least one, that’s sufficient to prove a != b.
                //
                // Note:
                // - If cmp_eq == 0, then it is impossible to have sum != 0 if a == b.
                // - If cmp_eq == 1, then it is impossible for a[i] - b[i] == 0 to pass for all i if a != b.
                #[allow(clippy::needless_range_loop)]
                for i in 0..UINT_LIMBS {
                    sum += (read_rs1.limbs[i].expr() - read_rs2.limbs[i].expr())
                        * eq_diff_inv_marker[i].expr();
                    circuit_builder.require_zero(
                        || "require_zero",
                        cmp_eq.expr() * (read_rs1.limbs[i].expr() - read_rs2.limbs[i].expr()),
                    )?
                }
                circuit_builder.require_one(|| "sum", sum)?;

                (
                    branch_taken_bit.expr(),
                    Some(branch_taken_bit),
                    Some(eq_diff_inv_marker),
                    None,
                )
            } else {
                let is_signed = matches!(I::INST_KIND, InsnKind::BLT | InsnKind::BGE);
                let is_ge = matches!(I::INST_KIND, InsnKind::BGEU | InsnKind::BGE);
                let uint_lt_config = UIntLimbsLT::<E>::construct_circuit(
                    circuit_builder,
                    &read_rs1,
                    &read_rs2,
                    is_signed,
                )?;
                let branch_taken_bit = if is_ge {
                    Expression::ONE - uint_lt_config.is_lt()
                } else {
                    uint_lt_config.is_lt()
                };
                (branch_taken_bit, None, None, Some(uint_lt_config))
            };

        let b_insn = BInstructionConfig::construct_circuit(
            circuit_builder,
            I::INST_KIND,
            read_rs1.register_expr(),
            read_rs2.register_expr(),
            branch_taken_bit_expr,
        )?;

        Ok(BranchConfig {
            b_insn,
            read_rs1,
            read_rs2,
            uint_lt_config,
            eq_branch_taken_bit,
            eq_diff_inv_marker,
            phantom: Default::default(),
        })
    }

    fn assign_instance(
        config: &Self::InstructionConfig,
        shard_ctx: &mut ShardContext,
        instance: &mut [E::BaseField],
        lk_multiplicity: &mut LkMultiplicity,
        step: &StepRecord,
    ) -> Result<(), ZKVMError> {
        config
            .b_insn
            .assign_instance(instance, shard_ctx, lk_multiplicity, step)?;

        let rs1 = Value::new_unchecked(step.rs1().unwrap().value);
        let rs1_limbs = rs1.as_u16_limbs();
        let rs2 = Value::new_unchecked(step.rs2().unwrap().value);
        let rs2_limbs = rs2.as_u16_limbs();
        config.read_rs1.assign_limbs(instance, rs1_limbs);
        config.read_rs2.assign_limbs(instance, rs2_limbs);

        if matches!(I::INST_KIND, InsnKind::BEQ | InsnKind::BNE) {
            // Returns (branch_taken, diff_idx, x[diff_idx] - y[diff_idx])
            #[inline(always)]
            fn run_eq<F, const NUM_LIMBS: usize>(
                is_beq: bool,
                x: &[u16],
                y: &[u16],
            ) -> (bool, usize, F)
            where
                F: FieldAlgebra + Field,
            {
                for i in 0..NUM_LIMBS {
                    if x[i] != y[i] {
                        return (
                            !is_beq,
                            i,
                            (F::from_canonical_u16(x[i]) - F::from_canonical_u16(y[i])).inverse(),
                        );
                    }
                }
                (is_beq, 0, F::ZERO)
            }
            let (branch_taken, diff_idx, diff_inv_val) = run_eq::<E::BaseField, UINT_LIMBS>(
                matches!(I::INST_KIND, InsnKind::BEQ),
                rs1_limbs,
                rs2_limbs,
            );
            set_val!(
                instance,
                config.eq_branch_taken_bit.as_ref().unwrap(),
                E::BaseField::from_bool(branch_taken)
            );
            set_val!(
                instance,
                config.eq_diff_inv_marker.as_ref().unwrap()[diff_idx],
                diff_inv_val
            );
        } else {
            let is_signed = matches!(step.insn().kind, InsnKind::BLT | InsnKind::BGE);
            UIntLimbsLT::<E>::assign(
                config.uint_lt_config.as_ref().unwrap(),
                instance,
                lk_multiplicity,
                rs1_limbs,
                rs2_limbs,
                is_signed,
            )?;
        }
        Ok(())
    }
}
