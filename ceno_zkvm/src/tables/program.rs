use super::RMMCollections;
use crate::{
    circuit_builder::{CircuitBuilder, SetTableSpec},
    error::ZKVMError,
    instructions::riscv::constants::LIMB_BITS,
    structs::{ProgramParams, ROMType},
    tables::TableCircuit,
};
use ceno_emul::{
    InsnFormat, InsnFormat::*, InsnKind::*, Instruction, PC_STEP_SIZE, Program, WORD_SIZE,
};
use ff_ext::{ExtensionField, FieldInto, SmallField};
use gkr_iop::utils::i64_to_base;
use itertools::Itertools;
use multilinear_extensions::{Expression, Fixed, ToExpr, WitIn};
use p3::field::FieldAlgebra;
use rayon::iter::{IndexedParallelIterator, ParallelIterator};
use std::{collections::HashMap, marker::PhantomData};
use witness::{InstancePaddingStrategy, RowMajorMatrix, set_fixed_val, set_val};

/// This structure establishes the order of the fields in instruction records, common to the program table and circuit fetches.
#[cfg(not(feature = "u16limb_circuit"))]
#[derive(Clone, Debug)]
pub struct InsnRecord<T>([T; 6]);
#[cfg(feature = "u16limb_circuit")]
#[derive(Clone, Debug)]
pub struct InsnRecord<T>([T; 7]);

impl<T> InsnRecord<T> {
    #[cfg(not(feature = "u16limb_circuit"))]
    pub fn new(pc: T, kind: T, rd: Option<T>, rs1: T, rs2: T, imm_internal: T) -> Self
    where
        T: From<u32>,
    {
        let rd = rd.unwrap_or_else(|| T::from(Instruction::RD_NULL));
        InsnRecord([pc, kind, rd, rs1, rs2, imm_internal])
    }

    #[cfg(feature = "u16limb_circuit")]
    pub fn new(pc: T, kind: T, rd: Option<T>, rs1: T, rs2: T, imm_internal: T, imm_sign: T) -> Self
    where
        T: From<u32>,
    {
        let rd = rd.unwrap_or_else(|| T::from(Instruction::RD_NULL));
        InsnRecord([pc, kind, rd, rs1, rs2, imm_internal, imm_sign])
    }

    pub fn as_slice(&self) -> &[T] {
        &self.0
    }
}

impl<F: SmallField> InsnRecord<F> {
    fn from_decoded(pc: u32, insn: &Instruction) -> Self {
        #[cfg(not(feature = "u16limb_circuit"))]
        {
            InsnRecord([
                (pc as u64).into_f(),
                (insn.kind as u64).into_f(),
                (insn.rd_internal() as u64).into_f(),
                (insn.rs1_or_zero() as u64).into_f(),
                (insn.rs2_or_zero() as u64).into_f(),
                InsnRecord::imm_internal(insn).1,
            ])
        }

        #[cfg(feature = "u16limb_circuit")]
        {
            InsnRecord([
                (pc as u64).into_f(),
                (insn.kind as u64).into_f(),
                (insn.rd_internal() as u64).into_f(),
                (insn.rs1_or_zero() as u64).into_f(),
                (insn.rs2_or_zero() as u64).into_f(),
                InsnRecord::imm_internal(insn).1,
                InsnRecord::<F>::imm_signed_internal(insn).1,
            ])
        }
    }
}

impl<F: SmallField> InsnRecord<F> {
    /// The internal view of the immediate in the program table.
    /// This is encoded in a way that is efficient for circuits, depending on the instruction.
    ///
    /// These conversions are legal:
    /// - `as u32` and `as i32` as usual.
    /// - `i64_to_base(imm)` gives the field element going into the program table.
    /// - `as u64` in unsigned cases.
    #[cfg(not(feature = "u16limb_circuit"))]
    pub fn imm_internal(insn: &Instruction) -> (i64, F) {
        match (insn.kind, InsnFormat::from(insn.kind)) {
            // Prepare the immediate for ShiftImmInstruction.
            // The shift is implemented as a multiplication/division by 1 << immediate.
            (SLLI | SRLI | SRAI, _) => (1 << insn.imm, i64_to_base(1 << insn.imm)),
            // Unsigned view.
            // For example, u32::MAX is `u32::MAX mod p` in the finite field
            (_, R | U) | (ADDI | SLTIU | ANDI | XORI | ORI, _) => {
                (insn.imm as u32 as i64, i64_to_base(insn.imm as u32 as i64))
            }
            // Signed view.
            // For example, u32::MAX is `-1 mod p` in the finite field.
            _ => (insn.imm as i64, i64_to_base(insn.imm as i64)),
        }
    }

    #[cfg(feature = "u16limb_circuit")]
    pub fn imm_internal(insn: &Instruction) -> (i64, F) {
        match (insn.kind, InsnFormat::from(insn.kind)) {
            // logic imm
            (XORI | ORI | ANDI, _) => (
                insn.imm as i16 as i64,
                F::from_canonical_u16(insn.imm as u16),
            ),
            // for imm operate with program counter => convert to field value
            (_, B | J) => (insn.imm as i64, i64_to_base(insn.imm as i64)),
            // AUIPC
            (AUIPC, U) => (
                // riv32 u type lower 12 bits are 0
                // take all except for least significant limb (8 bit)
                (insn.imm as u32 >> 8) as i64,
                F::from_wrapped_u32(insn.imm as u32 >> 8),
            ),
            // U type
            (_, U) => (
                (insn.imm as u32 >> 12) as i64,
                F::from_wrapped_u32(insn.imm as u32 >> 12),
            ),
            (JALR, _) => (
                insn.imm as i16 as i64,
                F::from_canonical_u16(insn.imm as i16 as u16),
            ),
            // for default imm to operate with register value
            _ => (
                insn.imm as i16 as i64,
                F::from_canonical_u16(insn.imm as i16 as u16),
            ),
        }
    }

    pub fn imm_signed_internal(insn: &Instruction) -> (i64, F) {
        match (insn.kind, InsnFormat::from(insn.kind)) {
            (SLLI | SRLI | SRAI, _) => (false as i64, F::from_bool(false)),
            // logic imm
            (XORI | ORI | ANDI, _) => (
                (insn.imm >> LIMB_BITS) as i16 as i64,
                F::from_canonical_u16((insn.imm >> LIMB_BITS) as u16),
            ),
            // Unsigned view.
            (_, R | U) => (false as i64, F::from_bool(false)),
            // in particular imm operated with program counter
            // encode as field element, which do not need extra sign extension of imm
            (_, B | J) => (false as i64, F::from_bool(false)),
            // Signed views
            _ => ((insn.imm < 0) as i64, F::from_bool(insn.imm < 0)),
        }
    }
}

#[derive(Clone, Debug)]
pub struct ProgramTableConfig {
    /// The fixed table of instruction records.
    record: InsnRecord<Fixed>,

    /// Multiplicity of the record - how many times an instruction is visited.
    mlt: WitIn,
    program_size: usize,
}

pub struct ProgramTableCircuit<E>(PhantomData<E>);

impl<E: ExtensionField> TableCircuit<E> for ProgramTableCircuit<E> {
    type TableConfig = ProgramTableConfig;
    type FixedInput = Program;
    type WitnessInput = Program;

    fn name() -> String {
        "PROGRAM".into()
    }

    fn construct_circuit(
        cb: &mut CircuitBuilder<E>,
        params: &ProgramParams,
    ) -> Result<ProgramTableConfig, ZKVMError> {
        #[cfg(not(feature = "u16limb_circuit"))]
        let record = InsnRecord([
            cb.create_fixed(|| "pc"),
            cb.create_fixed(|| "kind"),
            cb.create_fixed(|| "rd"),
            cb.create_fixed(|| "rs1"),
            cb.create_fixed(|| "rs2"),
            cb.create_fixed(|| "imm_internal"),
        ]);

        #[cfg(feature = "u16limb_circuit")]
        let record = InsnRecord([
            cb.create_fixed(|| "pc"),
            cb.create_fixed(|| "kind"),
            cb.create_fixed(|| "rd"),
            cb.create_fixed(|| "rs1"),
            cb.create_fixed(|| "rs2"),
            cb.create_fixed(|| "imm_internal"),
            cb.create_fixed(|| "imm_sign"),
        ]);

        let mlt = cb.create_witin(|| "mlt");

        let record_exprs = record
            .as_slice()
            .iter()
            .map(|f| Expression::Fixed(*f))
            .collect_vec();

        cb.lk_table_record(
            || "prog table",
            SetTableSpec {
                len: Some(params.program_size.next_power_of_two()),
                structural_witins: vec![],
            },
            ROMType::Instruction,
            record_exprs,
            mlt.expr(),
        )?;

        Ok(ProgramTableConfig {
            record,
            mlt,
            program_size: params.program_size,
        })
    }

    fn generate_fixed_traces(
        config: &ProgramTableConfig,
        num_fixed: usize,
        program: &Self::FixedInput,
    ) -> RowMajorMatrix<E::BaseField> {
        let num_instructions = program.instructions.len();
        let pc_base = program.base_address;
        assert!(num_instructions <= config.program_size);

        let mut fixed = RowMajorMatrix::<E::BaseField>::new(
            config.program_size,
            num_fixed,
            InstancePaddingStrategy::Default,
        );

        fixed
            .par_rows_mut()
            .zip(0..num_instructions)
            .for_each(|(row, i)| {
                let pc = pc_base + (i * PC_STEP_SIZE) as u32;
                let insn = program.instructions[i];
                let values: InsnRecord<_> = InsnRecord::from_decoded(pc, &insn);

                // Copy all the fields.
                for (col, val) in config.record.as_slice().iter().zip_eq(values.as_slice()) {
                    set_fixed_val!(row, *col, *val);
                }
            });

        fixed
    }

    fn assign_instances(
        config: &Self::TableConfig,
        num_witin: usize,
        num_structural_witin: usize,
        multiplicity: &[HashMap<u64, usize>],
        program: &Program,
    ) -> Result<RMMCollections<E::BaseField>, ZKVMError> {
        let multiplicity = &multiplicity[ROMType::Instruction as usize];

        let mut prog_mlt = vec![0_usize; program.instructions.len()];
        for (pc, mlt) in multiplicity {
            let i = (*pc as usize - program.base_address as usize) / WORD_SIZE;
            prog_mlt[i] = *mlt;
        }

        let mut witness = RowMajorMatrix::<E::BaseField>::new(
            config.program_size,
            num_witin + num_structural_witin,
            InstancePaddingStrategy::Default,
        );
        witness.par_rows_mut().zip(prog_mlt).for_each(|(row, mlt)| {
            set_val!(
                row,
                config.mlt,
                E::BaseField::from_canonical_u64(mlt as u64)
            );
        });

        Ok([witness, RowMajorMatrix::empty()])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        circuit_builder::ConstraintSystem, structs::ProgramParams, witness::LkMultiplicity,
    };
    use ceno_emul::encode_rv32;

    use ff_ext::GoldilocksExt2 as E;
    use p3::goldilocks::Goldilocks as F;

    #[test]
    fn test_program_padding() {
        let mut cs = ConstraintSystem::<E>::new(|| "riscv");
        let mut cb = CircuitBuilder::new(&mut cs);

        let actual_len = 3;
        let instructions = vec![encode_rv32(ADD, 1, 2, 3, 0); actual_len];
        let program = Program::new(
            0x2000_0000,
            0x2000_0000,
            0x2000_0000,
            instructions,
            Default::default(),
        );

        let params = ProgramParams::default();
        let config = ProgramTableCircuit::construct_circuit(&mut cb, &params).unwrap();

        let check = |matrix: &RowMajorMatrix<F>| {
            assert_eq!(
                matrix.num_instances() + matrix.num_padding_instances(),
                params.program_size
            );
            for row in matrix.iter_rows().skip(actual_len) {
                for col in row.iter() {
                    assert_eq!(*col, F::ZERO);
                }
            }
        };

        let fixed =
            ProgramTableCircuit::<E>::generate_fixed_traces(&config, cb.cs.num_fixed, &program);
        check(&fixed);

        let lkm = LkMultiplicity::default().into_finalize_result();

        let witness = ProgramTableCircuit::<E>::assign_instances(
            &config,
            cb.cs.num_witin as usize,
            cb.cs.num_structural_witin as usize,
            &lkm.0,
            &program,
        )
        .unwrap();
        check(&witness[0]);
    }
}
