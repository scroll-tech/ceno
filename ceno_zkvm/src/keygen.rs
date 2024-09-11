use crate::{
    error::ZKVMError,
    structs::{ZKVMConstraintSystem, ZKVMFixedTraces, ZKVMProvingKey},
};
use ff_ext::ExtensionField;

impl<E: ExtensionField> ZKVMConstraintSystem<E> {
    pub fn key_gen(
        self,
        mut vm_fixed_traces: ZKVMFixedTraces<E>,
    ) -> Result<ZKVMProvingKey<E>, ZKVMError> {
        let mut vm_pk = ZKVMProvingKey::default();

        for (c_name, cs) in self.circuit_css.into_iter() {
            let fixed_traces = vm_fixed_traces
                .circuit_fixed_traces
                .remove(&c_name)
                .ok_or(ZKVMError::FixedTraceNotFound(c_name.clone()))?;

            let circuit_pk = cs.key_gen(fixed_traces);
            assert!(vm_pk.circuit_pks.insert(c_name, circuit_pk).is_none());
        }

        Ok(vm_pk)
    }
}
