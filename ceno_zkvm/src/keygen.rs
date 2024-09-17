use crate::{
    error::ZKVMError,
    scheme::constants::MAX_NUM_VARIABLES,
    structs::{ZKVMConstraintSystem, ZKVMFixedTraces, ZKVMProvingKey},
};
use ff_ext::ExtensionField;
use mpcs::PolynomialCommitmentScheme;

impl<E: ExtensionField> ZKVMConstraintSystem<E> {
    pub fn key_gen<PCS: PolynomialCommitmentScheme<E>>(
        self,
        pp: PCS::Param,
        mut vm_fixed_traces: ZKVMFixedTraces<E>,
    ) -> Result<ZKVMProvingKey<E, PCS>, ZKVMError> {
        let mut vm_pk = ZKVMProvingKey::new(pp);
        let (pp, _) =
            PCS::trim(&vm_pk.pp, 1 << MAX_NUM_VARIABLES).map_err(|err| ZKVMError::PCSError(err))?;

        for (c_name, cs) in self.circuit_css.into_iter() {
            let fixed_traces = vm_fixed_traces
                .circuit_fixed_traces
                .remove(&c_name)
                .ok_or(ZKVMError::FixedTraceNotFound(c_name.clone()))?;

            let circuit_pk = cs.key_gen(&pp, fixed_traces);
            assert!(vm_pk.circuit_pks.insert(c_name, circuit_pk).is_none());
        }

        Ok(vm_pk)
    }
}
