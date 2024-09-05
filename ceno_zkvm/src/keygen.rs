use crate::{
    circuit_builder::{ZKVMConstraintSystem, ZKVMProvingKey},
    witness::RowMajorMatrix,
};
use ff_ext::ExtensionField;
use std::collections::BTreeMap;

impl<E: ExtensionField> ZKVMConstraintSystem<E> {
    pub fn key_gen(
        self,
        mut vm_fixed_traces: BTreeMap<String, Option<RowMajorMatrix<E::BaseField>>>,
    ) -> ZKVMProvingKey<E> {
        let mut vm_pk = ZKVMProvingKey::default();

        for (c_name, cs) in self.circuit_css.into_iter() {
            let fixed_traces = vm_fixed_traces.remove(&c_name).expect(
                format!(
                    "circuit {}'s trace is not present in vm_fixed_traces",
                    c_name
                )
                .as_str(),
            );

            let circuit_pk = cs.key_gen(fixed_traces);
            assert!(vm_pk.circuit_pks.insert(c_name, circuit_pk).is_none());
        }

        vm_pk
    }
}
