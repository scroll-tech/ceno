use super::field_wrapper::ExtensionFieldWrapper as FieldWrapper;
use ff_ext::ExtensionField;
use serde::Serialize;
use whir::ceno_binding::{WhirDefaultSpec as WhirDefaultSpecInner, WhirSpec as WhirSpecInner};

pub trait WhirSpec<E: ExtensionField>: Default + std::fmt::Debug + Clone {
    type Spec: WhirSpecInner<FieldWrapper<E>> + std::fmt::Debug + Default;
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct WhirDefaultSpec;

impl<E: ExtensionField> WhirSpec<E> for WhirDefaultSpec {
    type Spec = WhirDefaultSpecInner;
}
