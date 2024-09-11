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
use rayon::iter::{IndexedParallelIterator, IntoParallelIterator, ParallelIterator};

#[derive(Clone, Debug)]
pub struct ProgramTableConfig {
    pc: Fixed,
    // Decoded instruction fields.
    opcode: Fixed,
    rd: Fixed,
    funct3: Fixed,
    rs1: Fixed,
    rs2: Fixed,
    /// The complete immediate value, for instruction types I/S/B/U/J.
    /// Otherwise, the field funct7 of R-Type instructions.
    imm_or_funct7: Fixed,
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
        let pc = cb.create_fixed(|| "pc")?;
        let opcode = cb.create_fixed(|| "opcode")?;
        let rd = cb.create_fixed(|| "rd")?;
        let funct3 = cb.create_fixed(|| "funct3")?;
        let rs1 = cb.create_fixed(|| "rs1")?;
        let rs2 = cb.create_fixed(|| "rs2")?;
        let imm_or_funct7 = cb.create_fixed(|| "imm_or_funct7")?;

        let mlt = cb.create_witin(|| "mlt")?;

        let record_exprs = cb.rlc_chip_record(vec![
            Expression::Constant(E::BaseField::from(ROMType::Instruction as u64)),
            Expression::Fixed(pc.clone()),
            Expression::Fixed(opcode.clone()),
            Expression::Fixed(rd.clone()),
            Expression::Fixed(funct3.clone()),
            Expression::Fixed(rs1.clone()),
            Expression::Fixed(rs2.clone()),
            Expression::Fixed(imm_or_funct7.clone()),
        ]);

        cb.lk_table_record(|| "prog table", record_exprs, mlt.expr())?;

        Ok(ProgramTableConfig {
            pc,
            opcode,
            rd,
            funct3,
            rs1,
            rs2,
            imm_or_funct7,
            mlt,
        })
    }

    fn generate_fixed_traces(
        config: &ProgramTableConfig,
        num_fixed: usize,
        program: &[Word],
    ) -> RowMajorMatrix<E::BaseField> {
        // TODO: get bytecode of the program.
        let num_instructions = program.len();
        let pc_start = CENO_PLATFORM.pc_start() as u64;

        let mut fixed = RowMajorMatrix::<E::BaseField>::new(num_instructions, num_fixed);

        fixed
            .par_iter_mut()
            .with_min_len(MIN_PAR_SIZE)
            .zip((0..num_instructions).into_par_iter())
            .for_each(|(row, i)| {
                let pc = pc_start + (i * WORD_SIZE) as u64;
                let insn = DecodedInstruction::new(program[i]);

                tracing::debug!("pc=0x{:x} insn={:?}", pc, insn);

                for (col, val) in [
                    (&config.pc, pc as u32),
                    (&config.opcode, insn.opcode()),
                    (&config.rd, 0),
                    (&config.funct3, 0),
                    (&config.rs1, 0),
                    (&config.rs2, 0),
                    (&config.imm_or_funct7, 0),
                ] {
                    set_fixed_val!(row, *col, E::BaseField::from(val as u64));
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
        tracing::debug!(
            "num_instructions: {}. num_witin: {}",
            *num_instructions,
            num_witin,
        );

        let multiplicity = &multiplicity[ROMType::Instruction as usize];

        let mut prog_mlt = vec![0_usize; *num_instructions];
        for (pc, mlt) in multiplicity {
            let i = (*pc as usize - CENO_PLATFORM.pc_start() as usize) / WORD_SIZE;
            tracing::debug!("pc=0x{:x} index={} mlt={}", *pc, i, mlt);
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
