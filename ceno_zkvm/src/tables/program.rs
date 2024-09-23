use std::{collections::HashMap, marker::PhantomData, mem::MaybeUninit};

use crate::{
    circuit_builder::CircuitBuilder,
    error::ZKVMError,
    expression::{Expression, Fixed, ToExpr, WitIn},
    scheme::constants::MIN_PAR_SIZE,
    set_fixed_val, set_val,
    structs::ROMType,
    tables::TableCircuit,
    witness::RowMajorMatrix,
};
use ceno_emul::{DecodedInstruction, Word, CENO_PLATFORM, WORD_SIZE};
use ff_ext::ExtensionField;
use itertools::Itertools;
use rayon::iter::{IndexedParallelIterator, IntoParallelIterator, ParallelIterator};

#[derive(Clone, Debug)]
pub struct InsnRecord<T>([T; 7]);

impl<T> InsnRecord<T> {
    pub fn new(pc: T, opcode: T, rd: T, funct3: T, rs1: T, rs2: T, imm_or_funct7: T) -> Self {
        InsnRecord([pc, opcode, rd, funct3, rs1, rs2, imm_or_funct7])
    }

    pub fn as_slice(&self) -> &[T] {
        &self.0
    }

    pub fn pc(&self) -> &T {
        &self.0[0]
    }

    pub fn opcode(&self) -> &T {
        &self.0[1]
    }

    pub fn rd(&self) -> &T {
        &self.0[2]
    }

    pub fn funct3(&self) -> &T {
        &self.0[3]
    }

    pub fn rs1(&self) -> &T {
        &self.0[4]
    }

    pub fn rs2(&self) -> &T {
        &self.0[5]
    }

    /// The complete immediate value, for instruction types I/S/B/U/J.
    /// Otherwise, the field funct7 of R-Type instructions.
    pub fn imm_or_funct7(&self) -> &T {
        &self.0[6]
    }
}

impl InsnRecord<u32> {
    fn from_decoded(pc: u32, insn: &DecodedInstruction) -> Self {
        InsnRecord::new(
            pc,
            insn.opcode(),
            insn.rd(),
            insn.funct3(),
            insn.rs1(),
            insn.rs2(),
            insn.funct7(), // TODO: get immediate for all types.
        )
    }
}

#[derive(Clone, Debug)]
pub struct ProgramTableConfig {
    /// The fixed table of instruction records.
    record: InsnRecord<Fixed>,

    /// Multiplicity of the record - how many times an instruction is visited.
    mlt: WitIn,
}

pub struct ProgramTableCircuit<E>(PhantomData<E>);

impl<E: ExtensionField> TableCircuit<E> for ProgramTableCircuit<E> {
    type TableConfig = ProgramTableConfig;
    type FixedInput = [u32];
    type WitnessInput = usize;

    fn name() -> String {
        "PROGRAM".into()
    }

    fn construct_circuit(cb: &mut CircuitBuilder<E>) -> Result<ProgramTableConfig, ZKVMError> {
        let record = InsnRecord([
            cb.create_fixed(|| "pc")?,
            cb.create_fixed(|| "opcode")?,
            cb.create_fixed(|| "rd")?,
            cb.create_fixed(|| "funct3")?,
            cb.create_fixed(|| "rs1")?,
            cb.create_fixed(|| "rs2")?,
            cb.create_fixed(|| "imm_or_funct7")?,
        ]);

        let mlt = cb.create_witin(|| "mlt")?;

        let record_exprs = {
            let mut fields = vec![E::BaseField::from(ROMType::Instruction as u64).expr()];
            fields.extend(
                record
                    .as_slice()
                    .iter()
                    .map(|f| Expression::Fixed(f.clone())),
            );
            cb.rlc_chip_record(fields)
        };

        cb.lk_table_record(|| "prog table", record_exprs, mlt.expr())?;

        Ok(ProgramTableConfig { record, mlt })
    }

    fn generate_fixed_traces(
        config: &ProgramTableConfig,
        num_fixed: usize,
        program: &[Word],
    ) -> RowMajorMatrix<E::BaseField> {
        // TODO: get bytecode of the program.
        let num_instructions = program.len();
        let pc_start = CENO_PLATFORM.pc_start();

        let mut fixed = RowMajorMatrix::<E::BaseField>::new(num_instructions, num_fixed);

        fixed
            .par_iter_mut()
            .with_min_len(MIN_PAR_SIZE)
            .zip((0..num_instructions).into_par_iter())
            .for_each(|(row, i)| {
                let pc = pc_start + (i * WORD_SIZE) as u32;
                let insn = DecodedInstruction::new(program[i]);
                let values = InsnRecord::from_decoded(pc, &insn);

                for (col, val) in config.record.as_slice().iter().zip_eq(values.as_slice()) {
                    set_fixed_val!(row, *col, E::BaseField::from(*val as u64));
                }
            });

        fixed
    }

    fn assign_instances(
        config: &Self::TableConfig,
        num_witin: usize,
        multiplicity: &[HashMap<u64, usize>],
        num_instructions: &usize,
    ) -> Result<RowMajorMatrix<E::BaseField>, ZKVMError> {
        let multiplicity = &multiplicity[ROMType::Instruction as usize];

        let mut prog_mlt = vec![0_usize; *num_instructions];
        for (pc, mlt) in multiplicity {
            let i = (*pc as usize - CENO_PLATFORM.pc_start() as usize) / WORD_SIZE;
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
