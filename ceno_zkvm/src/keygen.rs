use std::collections::BTreeMap;

use crate::{
    error::ZKVMError,
    structs::{ZKVMConstraintSystem, ZKVMFixedTraces, ZKVMProvingKey},
};
use ff_ext::ExtensionField;
use mpcs::PolynomialCommitmentScheme;

impl<E: ExtensionField> ZKVMConstraintSystem<E> {
    pub fn key_gen<PCS: PolynomialCommitmentScheme<E>>(
        self,
        pp: PCS::ProverParam,
        vp: PCS::VerifierParam,
        entry_pc: u32,
        mut vm_fixed_traces: ZKVMFixedTraces<E>,
    ) -> Result<ZKVMProvingKey<E, PCS>, ZKVMError> {
        let mut vm_pk = ZKVMProvingKey::new(pp.clone(), vp);
        let mut fixed_traces = BTreeMap::new();
        let mut fixed_traces_no_omc_init = BTreeMap::new();

        for (circuit_index, (c_name, cs)) in self.circuit_css.into_iter().enumerate() {
            // fixed_traces is optional
            // verifier will check it existent if cs.num_fixed > 0
            if cs.num_fixed() > 0 {
                let fixed_trace_rmm = vm_fixed_traces
                    .circuit_fixed_traces
                    .remove(&c_name)
                    .flatten()
                    .ok_or(ZKVMError::FixedTraceNotFound(c_name.clone().into()))?;
                vm_pk
                    .circuit_index_fixed_num_instances
                    .insert(circuit_index, fixed_trace_rmm.num_instances());

                if !cs.with_omc_init_only() {
                    fixed_traces_no_omc_init.insert(circuit_index, fixed_trace_rmm.clone());
                }

                fixed_traces.insert(circuit_index, fixed_trace_rmm);
            }

            let circuit_pk = cs.key_gen();
            assert!(vm_pk.circuit_pks.insert(c_name, circuit_pk).is_none());
        }

        vm_pk.commit_fixed(fixed_traces, fixed_traces_no_omc_init)?;

        vm_pk.initial_global_state_expr = self.initial_global_state_expr;
        vm_pk.finalize_global_state_expr = self.finalize_global_state_expr;

        vm_pk.set_program_entry_pc(entry_pc);

        Ok(vm_pk)
    }
}
