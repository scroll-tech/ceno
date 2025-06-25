use ff_ext::ExtensionField;
use itertools::Itertools;
use std::{
    any::{Any, TypeId},
    collections::BTreeMap,
    marker::PhantomData,
    sync::{Arc, Mutex, OnceLock},
};

/// Precomputed extrapolation weights using the second form of barycentric interpolation.
///
/// This table supports extrapolation of univariate polynomials where:
/// - The known values are at integer points `x = 0, 1, ..., d`
/// - The degree `d` is in a fixed range [`min_degree`, `max_degree`]
/// - A univariate polynomial of degree `d` has exactly `d + 1` evaluation points
/// - The extrapolated values are computed at integer points `z > d`, up to `max_degree`
/// - No field inversions are required at runtime
///
/// The second form of the barycentric interpolation formula is:
///
/// ```text
/// L(z) = ∑_{j=0}^d (w_j / (z - x_j)) / ∑_{j=0}^d (w_j / (z - x_j)) * f(x_j)
///      = ∑_{j=0}^d v_j * f(x_j)
/// ```
///
/// Where:
/// - `x_j = j` (fixed integer evaluation points)
/// - `w_j = 1 / ∏_{i ≠ j} (x_j - x_i)` are barycentric weights (precomputed)
/// - `v_j = (w_j / (z - x_j)) / denom` are normalized interpolation coefficients (precomputed)
///
/// This structure stores all `v_j` coefficients for each `(degree, target_z)` pair.
/// At runtime, extrapolation is done by a simple dot product of `v_j` with the known values `f(x_j)`,
/// without needing any inverses.
pub struct ExtrapolationTable<E: ExtensionField> {
    /// weights[degree][z - degree - 1][j] = coefficient for f(x_j) when extrapolating to z
    pub weights: Vec<Vec<Vec<E>>>,
}

impl<E: ExtensionField> ExtrapolationTable<E> {
    pub fn new(min_degree: usize, max_degree: usize) -> Self {
        let mut weights = Vec::new();

        for d in min_degree..=max_degree {
            let mut degree_weights = Vec::new();

            let xs: Vec<E> = (0..=d as u64).map(E::from_canonical_u64).collect_vec();
            let mut bary_weights = Vec::new();

            // Compute barycentric weights w_j = 1 / prod_{i != j} (x_j - x_i)
            for j in 0..=d {
                let mut w = E::ONE;
                for i in 0..=d {
                    if i != j {
                        w *= xs[j] - xs[i];
                    }
                }
                bary_weights.push(w.inverse()); // safe because all x_i are distinct
            }

            for z_idx in d + 1..=max_degree {
                let z = E::from_canonical_u64(z_idx as u64);
                let mut den = E::ZERO;
                let mut tmp: Vec<E> = Vec::with_capacity(d + 1);

                for j in 0..=d {
                    let t = bary_weights[j] / (z - xs[j]);
                    tmp.push(t);
                    den += t;
                }

                // Normalize
                for t in tmp.iter_mut() {
                    *t = *t / den;
                }

                degree_weights.push(tmp);
            }

            weights.push(degree_weights);
        }

        Self { weights }
    }
}

pub struct ExtrapolationCache<E> {
    _marker: PhantomData<E>,
}

impl<E: ExtensionField> ExtrapolationCache<E> {
    fn global_cache() -> &'static Mutex<BTreeMap<TypeId, Box<dyn Any + Send + Sync>>> {
        static GLOBAL_CACHE: OnceLock<Mutex<BTreeMap<TypeId, Box<dyn Any + Send + Sync>>>> =
            OnceLock::new();
        GLOBAL_CACHE.get_or_init(|| Mutex::new(BTreeMap::new()))
    }

    #[allow(clippy::type_complexity)]
    fn cache_map() -> Arc<Mutex<BTreeMap<(usize, usize), Arc<ExtrapolationTable<E>>>>> {
        let global = Self::global_cache();
        let mut map = global.lock().unwrap();

        map.entry(TypeId::of::<E>())
            .or_insert_with(|| {
                Box::new(Arc::new(Mutex::new(BTreeMap::<
                    (usize, usize),
                    Arc<ExtrapolationTable<E>>,
                >::new()))) as Box<dyn Any + Send + Sync>
            })
            .downcast_ref::<Arc<Mutex<BTreeMap<(usize, usize), Arc<ExtrapolationTable<E>>>>>>()
            .expect("TypeId mapped to wrong type")
            .clone()
    }

    /// precompute and cache `ExtrapolationTable`s for all `(min_degree, max_degree)`
    /// pairs where `2 ≤ max_degree` and `1 ≤ min_degree < max_degree`.
    pub fn warm_up(max_degree: usize) {
        assert!(max_degree >= 2, "max_degree must be at least 2");

        for max in 2..=max_degree {
            for min in 1..max {
                let _ = Self::get(min, max);
            }
        }
    }

    /// get or create a cached `ExtrapolationTable` for the range `(min_degree, max_degree)`.
    pub fn get(min_degree: usize, max_degree: usize) -> Arc<ExtrapolationTable<E>> {
        let cache = Self::cache_map();
        let mut map = cache.lock().unwrap();

        if let Some(existing) = map.get(&(min_degree, max_degree)) {
            return existing.clone();
        }

        let table = Arc::new(ExtrapolationTable::new(min_degree, max_degree));
        map.insert((min_degree, max_degree), table.clone());
        table
    }
}
