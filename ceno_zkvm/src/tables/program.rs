use std::{collections::HashMap, marker::PhantomData, mem::MaybeUninit};

use crate::{
    circuit_builder::CircuitBuilder,
    error::ZKVMError,
    expression::{Expression, Fixed, ToExpr, WitIn},
    scheme::constants::MIN_PAR_SIZE,
    set_fixed_val, set_val,
    structs::ROMType,
    tables::TableCircuit,
    utils::i64_to_base,
    witness::RowMajorMatrix,
};
use ceno_emul::{
    DecodedInstruction, InsnCodes, InsnFormat::*, InsnKind::*, PC_STEP_SIZE, Program, WORD_SIZE,
};
use ff_ext::ExtensionField;
use goldilocks::SmallField;
use itertools::Itertools;
use rayon::iter::{IndexedParallelIterator, IntoParallelIterator, ParallelIterator};

#[macro_export]
macro_rules! declare_program {
    ($program:ident, $($instr:expr),* $(,)?) => {

        {
            let mut _i = 0;
            $(
                $program[_i] = $instr;
                _i += 1;
            )*
        }
    };
}

/// This structure establishes the order of the fields in instruction records, common to the program table and circuit fetches.
#[derive(Clone, Debug)]
pub struct InsnRecord<T>([T; 6]);

impl<T> InsnRecord<T> {
    pub fn new(pc: T, kind: T, rd: Option<T>, rs1: T, rs2: T, imm_internal: T) -> Self
    where
        T: From<u32>,
    {
        let rd = rd.unwrap_or_else(|| T::from(DecodedInstruction::RD_NULL));
        InsnRecord([pc, kind, rd, rs1, rs2, imm_internal])
    }

    pub fn as_slice(&self) -> &[T] {
        &self.0
    }
}

impl<F: SmallField> InsnRecord<F> {
    fn from_decoded(pc: u32, insn: &DecodedInstruction) -> Self {
        InsnRecord([
            (pc as u64).into(),
            (insn.codes().kind as u64).into(),
            (insn.rd_internal() as u64).into(),
            (insn.rs1_or_zero() as u64).into(),
            (insn.rs2_or_zero() as u64).into(),
            i64_to_base(InsnRecord::imm_internal(insn)),
        ])
    }
}

impl InsnRecord<()> {
    /// The internal view of the immediate in the program table.
    /// This is encoded in a way that is efficient for circuits, depending on the instruction.
    ///
    /// These conversions are legal:
    /// - `as u32` and `as i32` as usual.
    /// - `i64_to_base(imm)` gives the field element going into the program table.
    /// - `as u64` in unsigned cases.
    pub fn imm_internal(insn: &DecodedInstruction) -> i64 {
        let imm: u32 = insn.immediate();
        match insn.codes() {
            // Prepare the immediate for ShiftImmInstruction.
            // The shift is implemented as a multiplication/division by 1 << immediate.
            InsnCodes {
                kind: SLLI | SRLI | SRAI,
                ..
            } => 1 << (imm & 0x1F),
            // Unsigned view.
            // For example, u32::MAX is `u32::MAX mod p` in the finite field.
            InsnCodes { format: R | U, .. }
            | InsnCodes {
                kind: ADDI | SLTIU | ANDI | XORI | ORI,
                ..
            } => imm as u64 as i64,
            // Signed view.
            // For example, u32::MAX is `-1 mod p` in the finite field.
            _ => imm as i32 as i64,
        }
    }
}

#[derive(Clone, Debug)]
pub struct ProgramTableConfig {
    /// The fixed table of instruction records.
    record: InsnRecord<Fixed>,

    /// Multiplicity of the record - how many times an instruction is visited.
    mlt: WitIn,
}

pub struct ProgramTableCircuit<E, const PROGRAM_SIZE: usize>(PhantomData<E>);

impl<E: ExtensionField, const PROGRAM_SIZE: usize> TableCircuit<E>
    for ProgramTableCircuit<E, PROGRAM_SIZE>
{
    type TableConfig = ProgramTableConfig;
    type FixedInput = Program;
    type WitnessInput = Program;

    fn name() -> String {
        "PROGRAM".into()
    }

    fn construct_circuit(cb: &mut CircuitBuilder<E>) -> Result<ProgramTableConfig, ZKVMError> {
        let record = InsnRecord([
            cb.create_fixed(|| "pc")?,
            cb.create_fixed(|| "kind")?,
            cb.create_fixed(|| "rd")?,
            cb.create_fixed(|| "rs1")?,
            cb.create_fixed(|| "rs2")?,
            cb.create_fixed(|| "imm_internal")?,
        ]);

        let mlt = cb.create_witin(|| "mlt");

        let record_exprs = record
            .as_slice()
            .iter()
            .map(|f| Expression::Fixed(*f))
            .collect_vec();

        cb.lk_table_record(
            || "prog table",
            PROGRAM_SIZE,
            ROMType::Instruction,
            record_exprs,
            mlt.expr(),
        )?;

        Ok(ProgramTableConfig { record, mlt })
    }

    fn generate_fixed_traces(
        config: &ProgramTableConfig,
        num_fixed: usize,
        program: &Self::FixedInput,
    ) -> RowMajorMatrix<E::BaseField> {
        let num_instructions = program.instructions.len();
        let pc_base = program.base_address;
        assert!(num_instructions <= PROGRAM_SIZE);

        let mut fixed = RowMajorMatrix::<E::BaseField>::new(num_instructions, num_fixed);

        fixed
            .par_iter_mut()
            .with_min_len(MIN_PAR_SIZE)
            .zip((0..num_instructions).into_par_iter())
            .for_each(|(row, i)| {
                let pc = pc_base + (i * PC_STEP_SIZE) as u32;
                let insn = DecodedInstruction::new(program.instructions[i]);
                let values = InsnRecord::from_decoded(pc, &insn);

                // Copy all the fields.
                for (col, val) in config.record.as_slice().iter().zip_eq(values.as_slice()) {
                    set_fixed_val!(row, *col, *val);
                }
            });

        Self::padding_zero(&mut fixed, num_fixed).expect("padding error");
        fixed
    }

    fn assign_instances(
        config: &Self::TableConfig,
        num_witin: usize,
        multiplicity: &[HashMap<u64, usize>],
        program: &Program,
    ) -> Result<RowMajorMatrix<E::BaseField>, ZKVMError> {
        let multiplicity = &multiplicity[ROMType::Instruction as usize];

        let mut prog_mlt = vec![0_usize; program.instructions.len()];
        for (pc, mlt) in multiplicity {
            let i = (*pc as usize - program.base_address as usize) / WORD_SIZE;
            prog_mlt[i] = *mlt;
        }

        let mut witness = RowMajorMatrix::<E::BaseField>::new(prog_mlt.len(), num_witin);
        witness
            .par_iter_mut()
            .with_min_len(MIN_PAR_SIZE)
            .zip(prog_mlt.into_par_iter())
            .for_each(|(row, mlt)| {
                set_val!(row, config.mlt, E::BaseField::from(mlt as u64));
            });

        Ok(witness)
    }
}

#[cfg(test)]
#[test]
#[allow(clippy::identity_op)]
fn test_decode_imm() {
    for (i, expected) in [
        // Example of I-type: ADDI.
        // imm    | rs1     | funct3      | rd     | opcode
        (89 << 20 | 1 << 15 | 0b000 << 12 | 1 << 7 | 0x13, 89),
        // Shifts get a precomputed power of 2: SLLI, SRLI, SRAI.
        (31 << 20 | 1 << 15 | 0b001 << 12 | 1 << 7 | 0x13, 1 << 31),
        (31 << 20 | 1 << 15 | 0b101 << 12 | 1 << 7 | 0x13, 1 << 31),
        (
            1 << 30 | 31 << 20 | 1 << 15 | 0b101 << 12 | 1 << 7 | 0x13,
            1 << 31,
        ),
        // Example of R-type with funct7: SUB.
        // funct7     | rs2    | rs1     | funct3      | rd     | opcode
        (0x20 << 25 | 1 << 20 | 1 << 15 | 0 << 12 | 1 << 7 | 0x33, 0),
    ] {
        let imm = InsnRecord::imm_internal(&DecodedInstruction::new(i));
        assert_eq!(imm, expected);
    }
}
