use std::marker::PhantomData;

use ceno_emul::{InsnKind, StepIndex, StepRecord};
use ff_ext::{ExtensionField, FieldInto};
use gkr_iop::utils::lk_multiplicity::Multiplicity;
use multilinear_extensions::{Expression, StructuralWitIn, StructuralWitInType, ToExpr, WitIn};
use p3::field::PrimeCharacteristicRing;
use witness::{InstancePaddingStrategy, RowMajorMatrix};

use crate::{
    circuit_builder::CircuitBuilder,
    e2e::ShardContext,
    error::ZKVMError,
    instructions::Instruction,
    structs::{CustomRWTag, ProgramParams, RAMType},
    tables::RMMCollections,
    witness::{LkMultiplicity, set_val},
};

pub const TENSOR_BATCHED_MATMUL_CORE_NAME: &str = "TensorBatchedMatMulCore";
pub const TENSOR_BATCHED_MATMUL_A_COL: usize = 0;
pub const TENSOR_BATCHED_MATMUL_W_COL: usize = 3;
pub const TENSOR_BATCHED_MATMUL_Q_COL: usize = 6;
pub const TENSOR_BATCHED_MATMUL_R_COL: usize = 9;
pub const TENSOR_BATCHED_MATMUL_SCALE: i64 = 1 << 16;
pub const TENSOR_BATCHED_MATMUL_STATE_VERSION: u32 = 5;

#[derive(Clone, Debug)]
pub struct TensorBatchedMatMulSection {
    pub cycle: u64,
    pub call_id: u64,
    pub a: [[i8; 2]; 2],
    pub w: [[i8; 2]; 2],
}

pub(crate) fn tensor_batched_matmul_state_record<E: ExtensionField>(
    cycle: Expression<E>,
    call_id: Expression<E>,
    row: Expression<E>,
    a: Expression<E>,
    w: Expression<E>,
    q: Expression<E>,
    remainder: Expression<E>,
) -> Vec<Expression<E>> {
    vec![
        CustomRWTag::TensorState.expr::<E>(),
        E::BaseField::from_u32(TENSOR_BATCHED_MATMUL_STATE_VERSION).expr(),
        cycle,
        call_id,
        row,
        a,
        w,
        q,
        remainder,
    ]
}

#[derive(Debug)]
pub struct TensorBatchedMatMulCoreConfig {
    a: WitIn,
    a_magnitude: WitIn,
    a_sign: WitIn,
    w: WitIn,
    w_magnitude: WitIn,
    w_sign: WitIn,
    q: WitIn,
    q_magnitude: WitIn,
    q_sign: WitIn,
    remainder: WitIn,
    remainder_bits: [WitIn; 16],
    cycle: WitIn,
    call_id: WitIn,
    logical_row: WitIn,
    physical_logical_row: StructuralWitIn,
}

pub struct TensorBatchedMatMulCoreInstruction<E>(PhantomData<E>);

fn constrain_signed<E: ExtensionField>(
    cb: &mut CircuitBuilder<E>,
    name: &str,
    value: WitIn,
    magnitude: WitIn,
    sign: WitIn,
    bits: usize,
) -> Result<(), ZKVMError> {
    cb.assert_bit(|| format!("{name}_sign_bit"), sign.expr())?;
    cb.assert_const_range(|| format!("{name}_magnitude_range"), magnitude.expr(), bits)?;
    cb.require_equal(
        || format!("{name}_signed_value"),
        value.expr(),
        magnitude.expr() * (E::BaseField::ONE.expr() - sign.expr() * 2),
    )?;
    Ok(())
}

impl<E: ExtensionField> Instruction<E> for TensorBatchedMatMulCoreInstruction<E> {
    type InstructionConfig = TensorBatchedMatMulCoreConfig;
    type InsnType = InsnKind;

    fn inst_kinds() -> &'static [InsnKind] {
        &[]
    }

    fn name() -> String {
        TENSOR_BATCHED_MATMUL_CORE_NAME.into()
    }

    fn construct_circuit(
        cb: &mut CircuitBuilder<E>,
        _: &ProgramParams,
    ) -> Result<Self::InstructionConfig, ZKVMError> {
        // These stable offsets are opened directly by the matrix reduction.
        let a = cb.create_witin(|| "tensor_batched_a");
        let a_magnitude = cb.create_witin(|| "tensor_batched_a_magnitude");
        let a_sign = cb.create_witin(|| "tensor_batched_a_sign");
        let w = cb.create_witin(|| "tensor_batched_w");
        let w_magnitude = cb.create_witin(|| "tensor_batched_w_magnitude");
        let w_sign = cb.create_witin(|| "tensor_batched_w_sign");
        let q = cb.create_witin(|| "tensor_batched_q");
        let q_magnitude = cb.create_witin(|| "tensor_batched_q_magnitude");
        let q_sign = cb.create_witin(|| "tensor_batched_q_sign");
        let remainder = cb.create_witin(|| "tensor_batched_remainder");
        let remainder_bits =
            std::array::from_fn(|i| cb.create_witin(|| format!("tensor_batched_r_bit_{i}")));
        let cycle = cb.create_witin(|| "tensor_batched_cycle");
        let call_id = cb.create_witin(|| "tensor_batched_call_id");
        let logical_row = cb.create_witin(|| "tensor_batched_logical_row");
        let physical_logical_row = cb.create_structural_witin(
            || "tensor_batched_physical_logical_row",
            StructuralWitInType::OuterRepeatingIncrementalSequence { k: 2, n: 32 },
        );

        cb.require_equal(
            || "tensor_batched_logical_row_matches_physical_row",
            logical_row.expr(),
            physical_logical_row.expr(),
        )?;

        constrain_signed(cb, "tensor_batched_a", a, a_magnitude, a_sign, 8)?;
        constrain_signed(cb, "tensor_batched_w", w, w_magnitude, w_sign, 8)?;
        constrain_signed(cb, "tensor_batched_q", q, q_magnitude, q_sign, 16)?;
        for (i, bit) in remainder_bits.iter().enumerate() {
            cb.assert_bit(|| format!("tensor_batched_r_bit_{i}_boolean"), bit.expr())?;
        }
        let reconstructed = remainder_bits
            .iter()
            .enumerate()
            .fold(E::BaseField::ZERO.expr(), |acc, (i, bit)| {
                acc + bit.expr() * (1u64 << i)
            });
        cb.require_equal(
            || "tensor_batched_canonical_remainder",
            remainder.expr(),
            reconstructed,
        )?;
        cb.read_record(
            || "tensor_batched_matmul_state",
            RAMType::Custom,
            tensor_batched_matmul_state_record(
                cycle.expr(),
                call_id.expr(),
                logical_row.expr(),
                a.expr(),
                w.expr(),
                q.expr(),
                remainder.expr(),
            ),
        )?;

        Ok(TensorBatchedMatMulCoreConfig {
            a,
            a_magnitude,
            a_sign,
            w,
            w_magnitude,
            w_sign,
            q,
            q_magnitude,
            q_sign,
            remainder,
            remainder_bits,
            cycle,
            call_id,
            logical_row,
            physical_logical_row,
        })
    }

    fn assign_instance(
        _: &Self::InstructionConfig,
        _: &mut ShardContext,
        _: &mut [E::BaseField],
        _: &mut LkMultiplicity,
        _: &StepRecord,
    ) -> Result<(), ZKVMError> {
        Err(ZKVMError::InvalidWitness(
            "batched matmul Core is assigned by complete matrix sections".into(),
        ))
    }

    fn assign_instances(
        config: &Self::InstructionConfig,
        shard_ctx: &mut ShardContext,
        num_witin: usize,
        num_structural_witin: usize,
        steps: &[StepRecord],
        indices: &[StepIndex],
    ) -> Result<(RMMCollections<E::BaseField>, Multiplicity<u64>), ZKVMError> {
        let sections = indices
            .iter()
            .map(|index| {
                let step = &steps[*index];
                let syscall = step.syscall(&shard_ctx.syscall_witnesses).ok_or_else(|| {
                    ZKVMError::InvalidWitness("tiny batched MatMul syscall missing".into())
                })?;
                let payload = syscall.tensor_batched_matmul_2x2.ok_or_else(|| {
                    ZKVMError::InvalidWitness("tiny batched MatMul payload missing".into())
                })?;
                Ok(TensorBatchedMatMulSection {
                    cycle: step.cycle() - shard_ctx.current_shard_offset_cycle(),
                    call_id: syscall.reg_ops[0].value.after as u64,
                    a: payload.a,
                    w: payload.w,
                })
            })
            .collect::<Result<Vec<_>, ZKVMError>>()?;
        Self::assign_sections(config, num_witin, num_structural_witin, &sections)
    }
}

impl<E: ExtensionField> TensorBatchedMatMulCoreInstruction<E> {
    pub fn assign_sections(
        config: &TensorBatchedMatMulCoreConfig,
        num_witin: usize,
        num_structural_witin: usize,
        sections: &[TensorBatchedMatMulSection],
    ) -> Result<(RMMCollections<E::BaseField>, Multiplicity<u64>), ZKVMError> {
        if sections.is_empty() {
            return Err(ZKVMError::InvalidWitness(
                "batched matmul needs at least one complete section".into(),
            ));
        }
        let rows = sections.len() * 4;
        let mut witness = RowMajorMatrix::new(rows, num_witin, InstancePaddingStrategy::Default);
        let mut structural =
            RowMajorMatrix::new(rows, num_structural_witin, InstancePaddingStrategy::Default);
        let mut lkm = LkMultiplicity::default();

        for (physical_row, (row, structural_row)) in
            witness.iter_mut().zip(structural.iter_mut()).enumerate()
        {
            let section = &sections[physical_row / 4];
            let logical_row = physical_row % 4;
            if num_structural_witin > 0 {
                *structural_row.last_mut().unwrap() = E::BaseField::ONE;
            }
            let k = logical_row & 1;
            let m = logical_row >> 1;
            let n = logical_row & 1;
            let wk = logical_row >> 1;
            let acc = (0..2)
                .map(|inner| i64::from(section.a[m][inner]) * i64::from(section.w[inner][n]))
                .sum::<i64>();
            let q = acc.div_euclid(TENSOR_BATCHED_MATMUL_SCALE);
            let remainder = acc.rem_euclid(TENSOR_BATCHED_MATMUL_SCALE) as u64;

            set_val!(row, config.cycle, section.cycle);
            set_val!(row, config.call_id, section.call_id);
            set_val!(row, config.logical_row, logical_row as u64);
            set_val!(
                structural_row,
                config.physical_logical_row,
                logical_row as u64
            );

            assign_signed(
                config.a,
                config.a_magnitude,
                config.a_sign,
                row,
                &mut lkm,
                i64::from(section.a[m][k]),
                8,
            );
            assign_signed(
                config.w,
                config.w_magnitude,
                config.w_sign,
                row,
                &mut lkm,
                i64::from(section.w[wk][n]),
                8,
            );
            assign_signed(
                config.q,
                config.q_magnitude,
                config.q_sign,
                row,
                &mut lkm,
                q,
                16,
            );
            set_val!(row, config.remainder, remainder);
            for (i, bit) in config.remainder_bits.iter().enumerate() {
                set_val!(row, *bit, (remainder >> i) & 1);
            }
        }
        witness.padding_by_strategy();
        structural.padding_by_strategy();
        Ok(([witness, structural], lkm.into_finalize_result()))
    }
}

fn assign_signed<F: PrimeCharacteristicRing>(
    value_col: WitIn,
    magnitude_col: WitIn,
    sign_col: WitIn,
    row: &mut [F],
    lkm: &mut LkMultiplicity,
    value: i64,
    bits: usize,
) {
    let magnitude = value.unsigned_abs();
    row[value_col.id as usize] = if value < 0 {
        -F::from_u64(magnitude)
    } else {
        F::from_u64(magnitude)
    };
    row[magnitude_col.id as usize] = F::from_u64(magnitude);
    row[sign_col.id as usize] = F::from_u64(u64::from(value < 0));
    lkm.assert_const_range(magnitude, bits);
}
