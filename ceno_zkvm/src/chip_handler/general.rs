use ff_ext::ExtensionField;
use gkr_iop::{error::CircuitBuilderError, tables::LookupTable};

use crate::{
    circuit_builder::CircuitBuilder,
    instructions::riscv::constants::{
        END_CYCLE_IDX, END_PC_IDX, EXIT_CODE_IDX, HEAP_LENGTH_IDX, HEAP_START_ADDR_IDX,
        HINT_LENGTH_IDX, HINT_START_ADDR_IDX, INIT_CYCLE_IDX, INIT_PC_IDX, PUBLIC_IO_IDX,
        SHARD_ID_IDX, SHARD_RW_SUM_IDX, UINT_LIMBS,
    },
    scheme::constants::SEPTIC_EXTENSION_DEGREE,
    tables::InsnRecord,
};
use multilinear_extensions::{Expression, Instance};

pub trait InstFetch<E: ExtensionField> {
    fn lk_fetch(&mut self, record: &InsnRecord<Expression<E>>) -> Result<(), CircuitBuilderError>;
}

pub trait PublicValuesQuery {
    fn query_exit_code(&mut self) -> Result<[Instance; UINT_LIMBS], CircuitBuilderError>;
    fn query_init_pc(&mut self) -> Result<Instance, CircuitBuilderError>;
    fn query_init_cycle(&mut self) -> Result<Instance, CircuitBuilderError>;
    fn query_end_pc(&mut self) -> Result<Instance, CircuitBuilderError>;
    fn query_end_cycle(&mut self) -> Result<Instance, CircuitBuilderError>;
    fn query_global_rw_sum(&mut self) -> Result<Vec<Instance>, CircuitBuilderError>;
    fn query_public_io(&mut self) -> Result<[Instance; UINT_LIMBS], CircuitBuilderError>;
    #[allow(dead_code)]
    fn query_shard_id(&mut self) -> Result<Instance, CircuitBuilderError>;
    fn query_heap_start_addr(&self) -> Result<Instance, CircuitBuilderError>;
    #[allow(dead_code)]
    fn query_heap_shard_len(&self) -> Result<Instance, CircuitBuilderError>;
    fn query_hint_start_addr(&self) -> Result<Instance, CircuitBuilderError>;
    #[allow(dead_code)]
    fn query_hint_shard_len(&self) -> Result<Instance, CircuitBuilderError>;
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

impl<'a, E: ExtensionField> PublicValuesQuery for CircuitBuilder<'a, E> {
    fn query_exit_code(&mut self) -> Result<[Instance; UINT_LIMBS], CircuitBuilderError> {
        Ok([
            self.cs.query_instance(EXIT_CODE_IDX)?,
            self.cs.query_instance(EXIT_CODE_IDX + 1)?,
        ])
    }

    fn query_init_pc(&mut self) -> Result<Instance, CircuitBuilderError> {
        self.cs.query_instance(INIT_PC_IDX)
    }

    fn query_init_cycle(&mut self) -> Result<Instance, CircuitBuilderError> {
        self.cs.query_instance(INIT_CYCLE_IDX)
    }

    fn query_end_pc(&mut self) -> Result<Instance, CircuitBuilderError> {
        self.cs.query_instance(END_PC_IDX)
    }

    fn query_end_cycle(&mut self) -> Result<Instance, CircuitBuilderError> {
        self.cs.query_instance(END_CYCLE_IDX)
    }

    fn query_global_rw_sum(&mut self) -> Result<Vec<Instance>, CircuitBuilderError> {
        let x = (0..SEPTIC_EXTENSION_DEGREE)
            .map(|i| self.cs.query_instance(SHARD_RW_SUM_IDX + i))
            .collect::<Result<Vec<Instance>, CircuitBuilderError>>()?;
        let y = (0..SEPTIC_EXTENSION_DEGREE)
            .map(|i| {
                self.cs
                    .query_instance(SHARD_RW_SUM_IDX + SEPTIC_EXTENSION_DEGREE + i)
            })
            .collect::<Result<Vec<Instance>, CircuitBuilderError>>()?;

        Ok([x, y].concat())
    }

    fn query_public_io(&mut self) -> Result<[Instance; UINT_LIMBS], CircuitBuilderError> {
        Ok([
            self.cs.query_instance_for_openings(PUBLIC_IO_IDX)?,
            self.cs.query_instance_for_openings(PUBLIC_IO_IDX + 1)?,
        ])
    }

    fn query_shard_id(&mut self) -> Result<Instance, CircuitBuilderError> {
        self.cs.query_instance(SHARD_ID_IDX)
    }

    fn query_heap_start_addr(&self) -> Result<Instance, CircuitBuilderError> {
        self.cs.query_instance(HEAP_START_ADDR_IDX)
    }

    fn query_heap_shard_len(&self) -> Result<Instance, CircuitBuilderError> {
        self.cs.query_instance(HEAP_LENGTH_IDX)
    }

    fn query_hint_start_addr(&self) -> Result<Instance, CircuitBuilderError> {
        self.cs.query_instance(HINT_START_ADDR_IDX)
    }
    fn query_hint_shard_len(&self) -> Result<Instance, CircuitBuilderError> {
        self.cs.query_instance(HINT_LENGTH_IDX)
    }
}
