use std::{collections::HashMap, marker::PhantomData, mem::MaybeUninit};

use crate::{
    circuit_builder::CircuitBuilder,
    error::ZKVMError,
    expression::{Expression, Fixed, ToExpr, WitIn},
    scheme::constants::MIN_PAR_SIZE,
    set_fixed_val, set_val,
    structs::ROMType,
    tables::TableCircuit,
    uint::constants::RANGE_CHIP_BIT_WIDTH,
    witness::RowMajorMatrix,
};
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
    type Input = [u32];

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
        _input: &[u32],
    ) -> RowMajorMatrix<E::BaseField> {
        // TODO: get bytecode of the program.
        let num_instructions = 1 << RANGE_CHIP_BIT_WIDTH;

        let mut fixed = RowMajorMatrix::<E::BaseField>::new(num_instructions, num_fixed);

        fixed
            .par_iter_mut()
            .with_min_len(MIN_PAR_SIZE)
            .zip((0..num_instructions).into_par_iter())
            .for_each(|(row, i)| {
                set_fixed_val!(row, config.pc.0, E::BaseField::from(0 as u64));
                set_fixed_val!(row, config.opcode.0, E::BaseField::from(0 as u64));
                set_fixed_val!(row, config.rd.0, E::BaseField::from(0 as u64));
                set_fixed_val!(row, config.funct3.0, E::BaseField::from(0 as u64));
                set_fixed_val!(row, config.rs1.0, E::BaseField::from(0 as u64));
                set_fixed_val!(row, config.rs2.0, E::BaseField::from(0 as u64));
                set_fixed_val!(row, config.imm_or_funct7.0, E::BaseField::from(0 as u64));
            });

        fixed
    }

    fn assign_instances(
        config: &Self::TableConfig,
        num_witin: usize,
        multiplicity: &[HashMap<u64, usize>],
    ) -> Result<RowMajorMatrix<E::BaseField>, ZKVMError> {
        // TODO: get instruction count.
        tracing::debug!("num_witin: {}", num_witin);
        let num_instructions = 1 << RANGE_CHIP_BIT_WIDTH;

        let multiplicity = &multiplicity[ROMType::Instruction as usize];
        tracing::debug!("multiplicity: {:?}", multiplicity);

        let mut prog_mlt = vec![0_usize; num_instructions];
        for (limb, mlt) in multiplicity {
            prog_mlt[*limb as usize] = *mlt;
        }

        let mut witness = RowMajorMatrix::<E::BaseField>::new(prog_mlt.len(), num_witin);
        witness
            .par_iter_mut()
            .with_min_len(MIN_PAR_SIZE)
            .zip(prog_mlt.into_par_iter())
            .for_each(|(row, mlt)| {
                set_val!(row, config.mlt, E::BaseField::from(0 as u64)); // TODO
            });

        Ok(witness)
    }
}
