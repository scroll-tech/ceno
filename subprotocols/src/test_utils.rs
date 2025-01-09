use ff::PrimeField;
use ff_ext::ExtensionField;
use itertools::Itertools;
use rand::RngCore;

pub fn random_point<E: ExtensionField>(mut rng: impl RngCore, num_vars: usize) -> Vec<E> {
    (0..num_vars).map(|_| E::random(&mut rng)).collect_vec()
}

pub fn random_vec<E: ExtensionField>(mut rng: impl RngCore, len: usize) -> Vec<E> {
    (0..len).map(|_| E::random(&mut rng)).collect_vec()
}

pub fn random_poly<E: PrimeField>(mut rng: impl RngCore, num_vars: usize) -> Vec<E> {
    (0..1 << num_vars)
        .map(|_| E::random(&mut rng))
        .collect_vec()
}

#[macro_export]
macro_rules! field_vec {
    () => (
        $crate::vec::Vec::new()
    );
    ($field_type:ident; $elem:expr; $n:expr) => (
        $crate::vec::from_elem({
            if $x < 0 {
                -$field_type::from((-$x) as u64)
            } else {
                $field_type::from($x as u64)
            }
        }, $n)
    );
    ($field_type:ident, $($x:expr),+ $(,)?) => (
        <[_]>::into_vec(
            std::boxed::Box::new([$({
                let x = $x as i64;
                if $x < 0 {
                    -$field_type::from((-x) as u64)
                } else {
                    $field_type::from(x as u64)
                }
            }),+])
        )
    );
}
