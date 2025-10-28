use ff_ext::ExtensionField;
use gkr_iop::{error::CircuitBuilderError, tables::LookupTable};

use crate::{
    circuit_builder::CircuitBuilder,
    instructions::riscv::constants::{
        END_CYCLE_IDX, END_PC_IDX, EXIT_CODE_IDX, GLOBAL_RW_SUM_IDX, INIT_CYCLE_IDX, INIT_PC_IDX,
        PUBLIC_IO_IDX, UINT_LIMBS,
    },
    scheme::constants::SEPTIC_EXTENSION_DEGREE,
    tables::InsnRecord,
};
use multilinear_extensions::{Expression, Instance};

pub trait InstFetch<E: ExtensionField> {
    fn lk_fetch(&mut self, record: &InsnRecord<Expression<E>>) -> Result<(), CircuitBuilderError>;
}

pub trait PublicIOQuery {
    fn query_exit_code(&mut self) -> Result<[Instance; UINT_LIMBS], CircuitBuilderError>;
    fn query_init_pc(&mut self) -> Result<Instance, CircuitBuilderError>;
    fn query_init_cycle(&mut self) -> Result<Instance, CircuitBuilderError>;
    fn query_end_pc(&mut self) -> Result<Instance, CircuitBuilderError>;
    fn query_end_cycle(&mut self) -> Result<Instance, CircuitBuilderError>;
    fn query_global_rw_sum(&mut self) -> Result<Vec<Instance>, CircuitBuilderError>;
    fn query_public_io(&mut self) -> Result<[Instance; UINT_LIMBS], CircuitBuilderError>;
}

impl<'a, E: ExtensionField> InstFetch<E> for CircuitBuilder<'a, E> {
    /// Fetch an instruction at a given PC from the Program table.
    fn lk_fetch(&mut self, record: &InsnRecord<Expression<E>>) -> Result<(), CircuitBuilderError> {
        self.lk_record(
            || "fetch",
            LookupTable::Instruction,
            record.as_slice().to_vec(),
        )
    }
}

impl<'a, E: ExtensionField> PublicIOQuery for CircuitBuilder<'a, E> {
    fn query_exit_code(&mut self) -> Result<[Instance; UINT_LIMBS], CircuitBuilderError> {
        Ok([
            self.cs.query_instance(|| "exit_code_low", EXIT_CODE_IDX)?,
            self.cs
                .query_instance(|| "exit_code_high", EXIT_CODE_IDX + 1)?,
        ])
    }

    fn query_init_pc(&mut self) -> Result<Instance, CircuitBuilderError> {
        self.cs.query_instance(|| "init_pc", INIT_PC_IDX)
    }

    fn query_init_cycle(&mut self) -> Result<Instance, CircuitBuilderError> {
        self.cs.query_instance(|| "init_cycle", INIT_CYCLE_IDX)
    }

    fn query_end_pc(&mut self) -> Result<Instance, CircuitBuilderError> {
        self.cs.query_instance(|| "end_pc", END_PC_IDX)
    }

    fn query_end_cycle(&mut self) -> Result<Instance, CircuitBuilderError> {
        self.cs.query_instance(|| "end_cycle", END_CYCLE_IDX)
    }

    fn query_public_io(&mut self) -> Result<[Instance; UINT_LIMBS], CircuitBuilderError> {
        Ok([
            self.cs.query_instance(|| "public_io_low", PUBLIC_IO_IDX)?,
            self.cs
                .query_instance(|| "public_io_high", PUBLIC_IO_IDX + 1)?,
        ])
    }

    fn query_global_rw_sum(&mut self) -> Result<Vec<Instance>, CircuitBuilderError> {
        let x = (0..SEPTIC_EXTENSION_DEGREE)
            .map(|i| {
                self.cs
                    .query_instance(|| format!("global_rw_sum_x_{}", i), GLOBAL_RW_SUM_IDX + i)
            })
            .collect::<Result<Vec<Instance>, CircuitBuilderError>>()?;
        let y = (0..SEPTIC_EXTENSION_DEGREE)
            .map(|i| {
                self.cs.query_instance(
                    || format!("global_rw_sum_y_{}", i),
                    GLOBAL_RW_SUM_IDX + SEPTIC_EXTENSION_DEGREE + i,
                )
            })
            .collect::<Result<Vec<Instance>, CircuitBuilderError>>()?;

        Ok([x, y].concat())
    }
}
