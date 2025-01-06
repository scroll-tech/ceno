use super::{WhirSpec, field_wrapper::ExtensionFieldWrapper as FieldWrapper};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ff_ext::ExtensionField;
use serde::{Deserialize, Serialize};
use whir::ceno_binding::InnerDigestOf as InnerDigestOfInner;

type InnerDigestOf<Spec, E> = InnerDigestOfInner<<Spec as WhirSpec<E>>::Spec, FieldWrapper<E>>;

#[derive(Default, Clone, Debug)]
pub struct WhirDigest<E: ExtensionField, Spec: WhirSpec<E>> {
    pub(crate) inner: InnerDigestOf<Spec, E>,
}

impl<E: ExtensionField, Spec: WhirSpec<E>> Serialize for WhirDigest<E, Spec> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let digest = &self.inner;
        // Create a buffer that implements the `Write` trait
        let mut buffer = Vec::new();
        digest.serialize_compressed(&mut buffer).unwrap();
        serializer.serialize_bytes(&buffer)
    }
}

impl<'de, E: ExtensionField, Spec: WhirSpec<E>> Deserialize<'de> for WhirDigest<E, Spec> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        // Deserialize the bytes into a buffer
        let buffer: Vec<u8> = Deserialize::deserialize(deserializer)?;
        // Deserialize the buffer into a proof
        let inner = InnerDigestOf::<Spec, E>::deserialize_compressed(&buffer[..])
            .map_err(serde::de::Error::custom)?;
        Ok(WhirDigest { inner })
    }
}

pub fn digest_to_bytes<Spec: WhirSpec<E>, E: ExtensionField>(
    digest: &InnerDigestOf<Spec, E>,
) -> Result<Vec<u8>, crate::Error> {
    let mut buffer = Vec::new();
    digest
        .serialize_compressed(&mut buffer)
        .map_err(|err| crate::Error::Serialization(err.to_string()))?;
    Ok(buffer)
}
