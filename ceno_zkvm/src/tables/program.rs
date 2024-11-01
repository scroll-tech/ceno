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
use ceno_emul::{
    ActuallyDecodedInstruction as DecodedInstruction, PC_STEP_SIZE, Program, WORD_SIZE,
};
use ff_ext::ExtensionField;
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

#[derive(Clone, Debug)]
pub struct InsnRecord<T>([T; 6]);

impl<T> InsnRecord<T> {
    pub fn new(pc: T, kind: T, rd: T, rs1: T, rs2: T, imm: T) -> Self {
        InsnRecord([pc, kind, rd, rs1, rs2, imm])
    }

    pub fn as_slice(&self) -> &[T] {
        &self.0
    }

    pub fn pc(&self) -> &T {
        &self.0[0]
    }

    pub fn kind(&self) -> &T {
        &self.0[1]
    }

    pub fn rdo(&self) -> &T {
        &self.0[2]
    }

    pub fn rs1(&self) -> &T {
        &self.0[3]
    }

    pub fn rs2(&self) -> &T {
        &self.0[4]
    }

    // TODO: Remove this.  nothing complicated about imm anymore.
    /// Iterate through the fields, except immediate because it is complicated.
    fn without_imm(&self) -> &[T] {
        &self.0[0..5]
    }

    /// The internal view of the immediate. See `DecodedInstruction::imm_internal`.
    pub fn imm(&self) -> &T {
        &self.0[5]
    }
}

impl InsnRecord<i64> {
    fn from_decoded(pc: u32, insn: &DecodedInstruction) -> Self {
        InsnRecord::new(
            pc as i64,
            insn.kind as i64,
            insn.rd as i64,
            insn.rs1 as i64,
            insn.rs2 as i64,
            // TODO: review this, we actually nede to store whether it's signed.
            // What is this used for?
            insn.imm,
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
            cb.create_fixed(|| "opcode")?,
            cb.create_fixed(|| "rd")?,
            cb.create_fixed(|| "rs1")?,
            cb.create_fixed(|| "rs2")?,
            cb.create_fixed(|| "imm")?,
        ]);

        let mlt = cb.create_witin(|| "mlt");

        let record_exprs = {
            let mut fields = vec![E::BaseField::from(ROMType::Instruction as u64).expr()];
            fields.extend(record.as_slice().iter().map(|f| Expression::Fixed(*f)));
            cb.rlc_chip_record(fields)
        };

        cb.lk_table_record(|| "prog table", PROGRAM_SIZE, record_exprs, mlt.expr())?;

        Ok(ProgramTableConfig { record, mlt })
    }

    fn generate_fixed_traces(
        config: &ProgramTableConfig,
        num_fixed: usize,
        program: &Self::FixedInput,
    ) -> RowMajorMatrix<E::BaseField> {
        let num_instructions = program.instructions.len();
        let pc_base = program.base_address;

        let mut fixed = RowMajorMatrix::<E::BaseField>::new(num_instructions, num_fixed);

        fixed
            .par_iter_mut()
            .with_min_len(MIN_PAR_SIZE)
            .zip((0..num_instructions).into_par_iter())
            .for_each(|(row, i)| {
                let pc = pc_base + (i * PC_STEP_SIZE) as u32;
                let insn = DecodedInstruction::new(program.instructions[i]);
                let values = InsnRecord::from_decoded(pc, &insn);

                for (col, val) in config.record.0.iter().zip_eq(values.without_imm()) {
                    set_fixed_val!(row, *col, E::BaseField::from(*val as u64));
                }
            });

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
