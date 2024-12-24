use ff_ext::ExtensionField;
use multilinear_extensions::mle::DenseMultilinearExtension;
use plonky2::util::reverse_index_bits_in_place;
use whir::poly_utils::coeffs::CoefficientList;

use crate::util::arithmetic::interpolate_field_type_over_boolean_hypercube;

use super::ff_base::BaseFieldWrapper;

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
            reverse_index_bits_in_place(coeffs.as_mut_slice());
            CoefficientList::new(coeffs.iter().map(|x| BaseFieldWrapper(*x)).collect())
        }
        _ => unreachable!(),
    }
}

#[cfg(test)]
mod tests {
    use goldilocks::{Goldilocks, GoldilocksExt2};
    use multilinear_extensions::mle::{FieldType, MultilinearExtension};

    use crate::whir::ff::ExtensionFieldWrapper;

    use super::*;

    type E = GoldilocksExt2;

    #[test]
    fn test_evaluation_after_conversion() {
        let poly: DenseMultilinearExtension<E> =
            DenseMultilinearExtension::from_evaluations_vec(3, vec![
                Goldilocks::from(1),
                Goldilocks::from(2),
                Goldilocks::from(3),
                Goldilocks::from(4),
                Goldilocks::from(1),
                Goldilocks::from(2),
                Goldilocks::from(3),
                Goldilocks::from(4),
            ]);
        let mut coeffs = poly.clone();
        interpolate_field_type_over_boolean_hypercube(&mut coeffs.evaluations);

        assert_eq!(
            coeffs.evaluations,
            // 1 + X0 + 2X1
            FieldType::Base(vec![
                Goldilocks::from(1),
                Goldilocks::from(1),
                Goldilocks::from(2),
                Goldilocks::from(0),
                Goldilocks::from(0),
                Goldilocks::from(0),
                Goldilocks::from(0),
                Goldilocks::from(0),
            ])
        );

        let whir_poly = poly2whir(&poly);
        let point = [E::from(1), E::from(2), E::from(3)];
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
