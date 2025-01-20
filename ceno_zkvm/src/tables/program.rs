use std::{collections::HashMap, marker::PhantomData};

use crate::{
    circuit_builder::{CircuitBuilder, SetTableSpec},
    error::ZKVMError,
    expression::{Expression, Fixed, ToExpr, WitIn},
    instructions::InstancePaddingStrategy,
    scheme::constants::MIN_PAR_SIZE,
    set_fixed_val, set_val,
    structs::ROMType,
    tables::TableCircuit,
    utils::i64_to_base,
    witness::RowMajorMatrix,
};
use ceno_emul::{
    InsnFormat, InsnFormat::*, InsnKind::*, Instruction, PC_STEP_SIZE, Program, WORD_SIZE,
};
use ff_ext::ExtensionField;
use goldilocks::SmallField;
use itertools::Itertools;
use rayon::iter::{IndexedParallelIterator, IntoParallelIterator, ParallelIterator};

/// This structure establishes the order of the fields in instruction records, common to the program table and circuit fetches.
#[derive(Clone, Debug)]
pub struct InsnRecord<T>([T; 6]);

impl<T> InsnRecord<T> {
    pub fn new(pc: T, kind: T, rd: Option<T>, rs1: T, rs2: T, imm_internal: T) -> Self
    where
        T: From<u32>,
    {
        let rd = rd.unwrap_or_else(|| T::from(Instruction::RD_NULL));
        InsnRecord([pc, kind, rd, rs1, rs2, imm_internal])
    }

    pub fn as_slice(&self) -> &[T] {
        &self.0
    }
}

impl<F: SmallField> InsnRecord<F> {
    fn from_decoded(pc: u32, insn: &Instruction) -> Self {
        InsnRecord([
            (pc as u64).into(),
            (insn.kind as u64).into(),
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
    pub fn imm_internal(insn: &Instruction) -> i64 {
        match (insn.kind, InsnFormat::from(insn.kind)) {
            // Prepare the immediate for ShiftImmInstruction.
            // The shift is implemented as a multiplication/division by 1 << immediate.
            (SLLI | SRLI | SRAI, _) => 1 << insn.imm,
            // Unsigned view.
            // For example, u32::MAX is `u32::MAX mod p` in the finite field.
            (_, R | U) | (ADDI | SLTIU | ANDI | XORI | ORI, _) => insn.imm as u32 as i64,
            // Signed view.
            // For example, u32::MAX is `-1 mod p` in the finite field.
            _ => insn.imm as i64,
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
            SetTableSpec {
                len: Some(cb.params.program_size.next_power_of_two()),
                structural_witins: vec![],
            },
            ROMType::Instruction,
            record_exprs,
            mlt.expr(),
        )?;

        Ok(ProgramTableConfig {
            record,
            mlt,
            program_size: cb.params.program_size,
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
            .par_iter_mut()
            .with_min_len(MIN_PAR_SIZE)
            .zip((0..num_instructions).into_par_iter())
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
    ) -> Result<RowMajorMatrix<E::BaseField>, ZKVMError> {
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
mod tests {
    use super::*;
    use crate::{circuit_builder::ConstraintSystem, witness::LkMultiplicity};
    use ceno_emul::encode_rv32;
    use ff::Field;
    use goldilocks::{Goldilocks as F, GoldilocksExt2 as E};

    #[test]
    fn test_program_padding() {
        let mut cs = ConstraintSystem::<E>::new(|| "riscv");
        let mut cb = CircuitBuilder::new(&mut cs);

        let actual_len = 3;
        let instructions = vec![encode_rv32(ADD, 1, 2, 3, 0); actual_len];
        let program = Program::new(0x2000_0000, 0x2000_0000, instructions, Default::default());

        let config = ProgramTableCircuit::construct_circuit(&mut cb).unwrap();

        let check = |matrix: &RowMajorMatrix<F>| {
            assert_eq!(
                matrix.num_instances() + matrix.num_padding_instances(),
                cb.params.program_size
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
            &lkm,
            &program,
        )
        .unwrap();
        check(&witness);
    }
}
