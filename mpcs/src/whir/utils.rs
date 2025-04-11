use ff_ext::ExtensionField;
use multilinear_extensions::mle::DenseMultilinearExtension;
use p3::util::reverse_slice_index_bits;
use rayon::iter::{IntoParallelRefIterator, ParallelIterator};
use whir::poly_utils::coeffs::CoefficientList;

use crate::util::arithmetic::interpolate_field_type_over_boolean_hypercube;

use super::field_wrapper::BaseFieldWrapper;

pub fn poly2whir<E: ExtensionField>(
    poly: &DenseMultilinearExtension<E>,
) -> CoefficientList<BaseFieldWrapper<E>> {
    let mut poly = poly.clone();
    interpolate_field_type_over_boolean_hypercube(&mut poly.evaluations);
    // The coefficients for WHIR is stored in big endian, but our
    // poly is in little endian. So need to apply a bit-reverse permutation
    // to the coefficients.

    match &mut poly.evaluations {
        multilinear_extensions::mle::FieldType::Ext(_coeffs) => {
            panic!("WHIR only supports committing to base field polys now")
        }
        multilinear_extensions::mle::FieldType::Base(coeffs) => {
            reverse_slice_index_bits(coeffs.as_mut_slice());
            CoefficientList::new(coeffs.par_iter().map(|x| BaseFieldWrapper(*x)).collect())
        }
        _ => unreachable!(),
    }
}

pub fn polys2whir<E: ExtensionField>(
    poly: &[DenseMultilinearExtension<E>],
) -> Vec<CoefficientList<BaseFieldWrapper<E>>> {
    poly.par_iter().map(|poly| poly2whir(poly)).collect()
}

#[cfg(test)]
mod tests {
    use ff_ext::{FromUniformBytes, GoldilocksExt2};
    use multilinear_extensions::mle::{FieldType, MultilinearExtension};
    use p3::{field::PrimeCharacteristicRing, goldilocks::Goldilocks};
    use rand::rngs::OsRng;

    use crate::whir::field_wrapper::ExtensionFieldWrapper;

    use super::*;

    type E = GoldilocksExt2;

    #[test]
    fn test_evaluation_after_conversion() {
        let poly: DenseMultilinearExtension<E> =
            DenseMultilinearExtension::from_evaluations_vec(3, vec![
                Goldilocks::from_u16(1),
                Goldilocks::from_u16(2),
                Goldilocks::from_u16(3),
                Goldilocks::from_u16(4),
                Goldilocks::from_u16(1),
                Goldilocks::from_u16(2),
                Goldilocks::from_u16(3),
                Goldilocks::from_u16(4),
            ]);
        let mut coeffs = poly.clone();
        interpolate_field_type_over_boolean_hypercube(&mut coeffs.evaluations);

        assert_eq!(
            coeffs.evaluations,
            // 1 + X0 + 2X1
            FieldType::Base(vec![
                Goldilocks::from_u16(1),
                Goldilocks::from_u16(1),
                Goldilocks::from_u16(2),
                Goldilocks::from_u16(0),
                Goldilocks::from_u16(0),
                Goldilocks::from_u16(0),
                Goldilocks::from_u16(0),
                Goldilocks::from_u16(0),
            ])
        );

        let whir_poly = poly2whir(&poly);
        let point = [E::from_u16(1), E::from_u16(2), E::from_u16(3)];
        let whir_point = point
            .iter()
            .map(|x| ExtensionFieldWrapper(*x))
            .collect::<Vec<_>>();
        assert_eq!(
            ExtensionFieldWrapper(poly.evaluate(&point)),
            whir_poly
                .evaluate_at_extension(&whir::poly_utils::MultilinearPoint(whir_point.clone()))
        );
    }

    #[test]
    fn test_evaluation_for_random_polynomial() {
        let poly: DenseMultilinearExtension<E> = DenseMultilinearExtension::random(10, &mut OsRng);
        let mut coeffs = poly.clone();
        interpolate_field_type_over_boolean_hypercube(&mut coeffs.evaluations);

        let whir_poly = poly2whir(&poly);
        let point = [
            E::random(&mut OsRng),
            E::random(&mut OsRng),
            E::random(&mut OsRng),
            E::random(&mut OsRng),
            E::random(&mut OsRng),
            E::random(&mut OsRng),
            E::random(&mut OsRng),
            E::random(&mut OsRng),
            E::random(&mut OsRng),
            E::random(&mut OsRng),
        ];
        let whir_point = point
            .iter()
            .map(|x| ExtensionFieldWrapper(*x))
            .collect::<Vec<_>>();
        assert_eq!(
            ExtensionFieldWrapper(poly.evaluate(&point)),
            whir_poly
                .evaluate_at_extension(&whir::poly_utils::MultilinearPoint(whir_point.clone()))
        );
    }
}
