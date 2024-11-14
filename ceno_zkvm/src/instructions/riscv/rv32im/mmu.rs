use ff_ext::ExtensionField;

use crate::{
    error::ZKVMError,
    structs::{ZKVMConstraintSystem, ZKVMFixedTraces, ZKVMWitnesses},
    tables::{
        MemFinalRecord, MemInitRecord, ProgramDataCircuit, PubIOCircuit, RegTableCircuit,
        TableCircuit,
    },
};

pub struct MmuConfig<E: ExtensionField> {
    pub reg_config: <RegTableCircuit<E> as TableCircuit<E>>::TableConfig,
    pub program_data_config: <ProgramDataCircuit<E> as TableCircuit<E>>::TableConfig,
    pub public_io_config: <PubIOCircuit<E> as TableCircuit<E>>::TableConfig,
}

impl<E: ExtensionField> MmuConfig<E> {
    pub fn construct_circuits(cs: &mut ZKVMConstraintSystem<E>) -> Self {
        let reg_config = cs.register_table_circuit::<RegTableCircuit<E>>();

        let program_data_config = cs.register_table_circuit::<ProgramDataCircuit<E>>();

        let public_io_config = cs.register_table_circuit::<PubIOCircuit<E>>();

        Self {
            reg_config,
            program_data_config,
            public_io_config,
        }
    }

    pub fn generate_fixed_traces(
        &self,
        cs: &ZKVMConstraintSystem<E>,
        fixed: &mut ZKVMFixedTraces<E>,
        reg_init: &[MemInitRecord],
        program_data_init: &[MemInitRecord],
    ) {
        fixed.register_table_circuit::<RegTableCircuit<E>>(cs, &self.reg_config, reg_init);

        fixed.register_table_circuit::<ProgramDataCircuit<E>>(
            cs,
            &self.program_data_config,
            program_data_init,
        );

        fixed.register_table_circuit::<PubIOCircuit<E>>(cs, &self.public_io_config, &());
    }

    pub fn assign_table_circuit(
        &self,
        cs: &ZKVMConstraintSystem<E>,
        witness: &mut ZKVMWitnesses<E>,
        reg_final: &[MemFinalRecord],
        program_data_final: &[MemFinalRecord],
        public_io_final: &[MemFinalRecord],
    ) -> Result<(), ZKVMError> {
        witness.assign_table_circuit::<RegTableCircuit<E>>(cs, &self.reg_config, reg_final)?;

        witness.assign_table_circuit::<ProgramDataCircuit<E>>(
            cs,
            &self.program_data_config,
            program_data_final,
        )?;

        witness.assign_table_circuit::<PubIOCircuit<E>>(
            cs,
            &self.public_io_config,
            public_io_final,
        )?;

        Ok(())
    }
}
