use crate::{
    circuit_builder::{ZKVMConstraintSystem, ZKVMProvingKey},
    error::ZKVMError,
    witness::RowMajorMatrix,
};
use ff_ext::ExtensionField;
use std::collections::BTreeMap;

impl<E: ExtensionField> ZKVMConstraintSystem<E> {
    pub fn key_gen(
        self,
        mut vm_fixed_traces: BTreeMap<String, Option<RowMajorMatrix<E::BaseField>>>,
    ) -> Result<ZKVMProvingKey<E>, ZKVMError> {
        let mut vm_pk = ZKVMProvingKey::default();

        for (c_name, cs) in self.circuit_css.into_iter() {
            let fixed_traces = vm_fixed_traces
                .remove(&c_name)
                .ok_or(ZKVMError::FixedTraceNotFound(c_name.clone()))?;

            let circuit_pk = cs.key_gen(fixed_traces);
            assert!(vm_pk.circuit_pks.insert(c_name, circuit_pk).is_none());
        }

        Ok(vm_pk)
    }
}
