use ff_ext::ExtensionField;

use crate::{
    error::ZKVMError,
    structs::{ZKVMConstraintSystem, ZKVMFixedTraces, ZKVMWitnesses},
    tables::{MemFinalRecord, MemInitRecord, ProgramDataCircuit, TableCircuit},
};

pub struct MmuConfig<E: ExtensionField> {
    pub program_data_config: <ProgramDataCircuit<E> as TableCircuit<E>>::TableConfig,
}

impl<E: ExtensionField> MmuConfig<E> {
    pub fn construct_circuits(cs: &mut ZKVMConstraintSystem<E>) -> Self {
        let program_data_config = cs.register_table_circuit::<ProgramDataCircuit<E>>();
        Self {
            program_data_config,
        }
    }

    pub fn generate_fixed_traces(
        &self,
        cs: &ZKVMConstraintSystem<E>,
        fixed: &mut ZKVMFixedTraces<E>,
        program_data_init: &[MemInitRecord],
    ) {
        fixed.register_table_circuit::<ProgramDataCircuit<E>>(
            cs,
            &self.program_data_config,
            program_data_init,
        );
    }

    pub fn assign_table_circuit(
        &self,
        cs: &ZKVMConstraintSystem<E>,
        witness: &mut ZKVMWitnesses<E>,
        program_data_final: &[MemFinalRecord],
    ) -> Result<(), ZKVMError> {
        witness.assign_table_circuit::<ProgramDataCircuit<E>>(
            cs,
            &self.program_data_config,
            program_data_final,
        )
    }
}
