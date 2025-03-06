use super::{
    WhirDefaultSpec, field_wrapper::ExtensionFieldWrapper as FieldWrapper, spec::WhirSpec,
};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ff_ext::ExtensionField;
use serde::{Deserialize, Serialize};
use whir::ceno_binding::{InnerDigestOf as InnerDigestOfInner, Whir as WhirInner};

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

pub(crate) type WhirInnerT<E, Spec> = WhirInner<FieldWrapper<E>, <Spec as WhirSpec<E>>::Spec>;

#[derive(Default, Clone, Debug, Serialize)]
pub struct Whir<E: ExtensionField, Spec: WhirSpec<E>> {
    inner: WhirInnerT<E, Spec>,
}

pub type WhirDefault<E> = Whir<E, WhirDefaultSpec>;

#[cfg(test)]
mod tests {
    use super::*;
    use ark_ff::Field;
    use ff_ext::GoldilocksExt2;
    use rand::Rng;
    use whir::{
        ceno_binding::{PolynomialCommitmentScheme, WhirDefaultSpec as WhirDefaultSpecInner},
        poly_utils::{Vec, coeffs::DenseMultilinearExtension},
    };

    type F = super::super::field_wrapper::ExtensionFieldWrapper<GoldilocksExt2>;

    #[test]
    fn whir_inner_commit_prove_verify() {
        let poly_size = 10;
        let num_coeffs = 1 << poly_size;
        WhirInner::<F, WhirDefaultSpecInner>::setup(num_coeffs as usize);

        let poly = DenseMultilinearExtension::new(
            (0..num_coeffs)
                .map(<F as Field>::BasePrimeField::from)
                .collect(),
        );

        let witness = WhirInner::<F, WhirDefaultSpecInner>::commit(&(), &poly).unwrap();
        let comm = witness.commitment;

        let mut rng = rand::thread_rng();
        let point: Vec<F> = (0..poly_size).map(|_| F::from(rng.gen::<u64>())).collect();
        let eval = poly.evaluate_at_extension(&Vec(point.clone()));

        let proof =
            WhirInner::<F, WhirDefaultSpecInner>::open(&(), &witness, &point, &eval).unwrap();
        WhirInner::<F, WhirDefaultSpecInner>::verify(&(), &comm, &point, &eval, &proof).unwrap();
    }
}
