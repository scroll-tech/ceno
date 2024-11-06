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
        mut vm_fixed_traces: ZKVMFixedTraces<E>,
    ) -> Result<ZKVMProvingKey<E, PCS>, ZKVMError> {
        let mut vm_pk = ZKVMProvingKey::new(pp, vp);

        for (c_name, cs) in self.circuit_css.into_iter() {
            // fixed_traces is optional
            // verifier will check it existent if cs.num_fixed > 0
            let fixed_traces = if cs.num_fixed > 0 {
                vm_fixed_traces
                    .circuit_fixed_traces
                    .remove(&c_name)
                    .ok_or(ZKVMError::FixedTraceNotFound(c_name.clone()))?
            } else {
                None
            };

            let circuit_pk = cs.key_gen(&vm_pk.pp, fixed_traces);
            assert!(vm_pk.circuit_pks.insert(c_name, circuit_pk).is_none());
        }

        vm_pk.initial_global_state_expr = self.initial_global_state_expr;
        vm_pk.finalize_global_state_expr = self.finalize_global_state_expr;

        Ok(vm_pk)
    }
}
