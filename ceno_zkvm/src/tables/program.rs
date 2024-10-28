use std::{collections::HashMap, marker::PhantomData, mem::MaybeUninit};

use crate::{
    circuit_builder::CircuitBuilder,
    error::ZKVMError,
    expression::{Expression, Fixed, ToExpr, WitIn},
    scheme::constants::MIN_PAR_SIZE,
    set_fixed_val, set_val,
    structs::ROMType,
    tables::{TableCircuit, views::columns_view_impl},
    witness::RowMajorMatrix,
};
use ceno_emul::{CENO_PLATFORM, DecodedInstruction, PC_STEP_SIZE, WORD_SIZE};
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

columns_view_impl!(InsnRecord);
#[repr(C)]
#[derive(Clone, Copy, Eq, PartialEq, Debug)]
pub struct InsnRecord<T> {
    pub pc: T,
    pub opcode: T,
    pub rd: T,
    pub funct3: T,
    pub rs1: T,
    pub rs2: T,
    /// The complete immediate value, for instruction types I/S/B/U/J.
    /// Otherwise, the field funct7 of R-Type instructions.
    pub imm_or_funct7: T,
}

impl<T> InsnRecord<T> {
    /// Iterate through the fields, except immediate because it is complicated.
    fn without_imm(&self) -> &[T] {
        &self[0..6]
    }
}

impl InsnRecord<u32> {
    fn from_decoded(pc: u32, insn: &DecodedInstruction) -> Self {
        InsnRecord {
            pc,
            opcode: insn.opcode(),
            rd: insn.rd_or_zero(),
            funct3: insn.funct3_or_zero(),
            rs1: insn.rs1_or_zero(),
            rs2: insn.rs2_or_zero(),
            imm_or_funct7: insn.imm_or_funct7(),
        }
    }

    /// Interpret the immediate or funct7 as unsigned or signed depending on the instruction.
    /// Convert negative values from two's complement to field.
    pub fn imm_or_funct7_field<F: SmallField>(insn: &DecodedInstruction) -> F {
        if insn.imm_is_negative() {
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
    type FixedInput = [u32; PROGRAM_SIZE];
    type WitnessInput = usize;

    fn name() -> String {
        "PROGRAM".into()
    }

    fn construct_circuit(cb: &mut CircuitBuilder<E>) -> Result<ProgramTableConfig, ZKVMError> {
        let record = InsnRecord {
            pc: cb.create_fixed(|| "pc")?,
            opcode: cb.create_fixed(|| "opcode")?,
            rd: cb.create_fixed(|| "rd")?,
            funct3: cb.create_fixed(|| "funct3")?,
            rs1: cb.create_fixed(|| "rs1")?,
            rs2: cb.create_fixed(|| "rs2")?,
            imm_or_funct7: cb.create_fixed(|| "imm_or_funct7")?,
        };

        let mlt = cb.create_witin(|| "mlt")?;

        let record_exprs = {
            let mut fields = vec![E::BaseField::from(ROMType::Instruction as u64).expr()];
            fields.extend(record.iter().map(|f| Expression::Fixed(*f)));
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
        // TODO: get bytecode of the program.
        let num_instructions = program.len();
        let pc_start = CENO_PLATFORM.pc_start();

        let mut fixed = RowMajorMatrix::<E::BaseField>::new(num_instructions, num_fixed);

        fixed
            .par_iter_mut()
            .with_min_len(MIN_PAR_SIZE)
            .zip((0..num_instructions).into_par_iter())
            .for_each(|(row, i)| {
                let pc = pc_start + (i * PC_STEP_SIZE) as u32;
                let insn = DecodedInstruction::new(program[i]);
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
                    config.record.imm_or_funct7,
                    InsnRecord::imm_or_funct7_field(&insn)
                );
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
