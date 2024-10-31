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
use ceno_emul::{DecodedInstruction, PC_STEP_SIZE, Program, WORD_SIZE};
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

#[derive(Clone, Debug)]
pub struct InsnRecord<T>([T; 7]);

impl<T> InsnRecord<T> {
    pub fn new(pc: T, opcode: T, rd: Option<T>, funct3: T, rs1: T, rs2: T, imm_or_funct7: T) -> Self
    where
        T: From<u32>,
    {
        let rd = rd.unwrap_or_else(|| T::from(DecodedInstruction::RD_NULL));
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

    pub fn rd_or_null(&self) -> &T {
        &self.0[2]
    }

    pub fn funct3_or_zero(&self) -> &T {
        &self.0[3]
    }

    pub fn rs1_or_zero(&self) -> &T {
        &self.0[4]
    }

    pub fn rs2_or_zero(&self) -> &T {
        &self.0[5]
    }

    /// Iterate through the fields, except immediate because it is complicated.
    fn without_imm(&self) -> &[T] {
        &self.0[0..6]
    }

    /// The complete immediate value, for instruction types I/S/B/U/J.
    /// Otherwise, the field funct7 of R-Type instructions.
    pub fn imm_or_funct7(&self) -> &T {
        &self.0[6]
    }
}

impl InsnRecord<u32> {
    fn from_decoded(pc: u32, insn: &DecodedInstruction) -> Self {
        InsnRecord([
            pc,
            insn.opcode(),
            insn.rd_internal(),
            insn.funct3_or_zero(),
            insn.rs1_or_zero(),
            insn.rs2_or_zero(),
            insn.imm_or_funct7(),
        ])
    }

    /// Interpret the immediate or funct7 as unsigned or signed depending on the instruction.
    /// Convert negative values from two's complement to field.
    pub fn imm_or_funct7_field<F: SmallField>(insn: &DecodedInstruction) -> F {
        if insn.imm_field_is_negative() {
            -F::from(-(insn.imm_or_funct7() as i32) as u64)
        } else {
            F::from(insn.imm_or_funct7() as u64)
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
            cb.create_fixed(|| "opcode")?,
            cb.create_fixed(|| "rd")?,
            cb.create_fixed(|| "funct3")?,
            cb.create_fixed(|| "rs1")?,
            cb.create_fixed(|| "rs2")?,
            cb.create_fixed(|| "imm_or_funct7")?,
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

                // Copy all the fields except immediate.
                for (col, val) in config
                    .record
                    .without_imm()
                    .iter()
                    .zip_eq(values.without_imm())
                {
                    set_fixed_val!(row, *col, E::BaseField::from(*val as u64));
                }

                set_fixed_val!(
                    row,
                    config.record.imm_or_funct7(),
                    InsnRecord::imm_or_funct7_field(&insn)
                );
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
