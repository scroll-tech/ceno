use std::{
    collections::{BTreeSet, HashMap},
    fmt::Display,
    hash::Hash,
    mem,
    panic::{self, PanicHookInfo},
};

use either::Either;
use ff_ext::{ExtensionField, SmallField};
use itertools::Itertools;
use multilinear_extensions::{
    Expression,
    mle::{ArcMultilinearExtension, MultilinearExtension},
    virtual_polys::VirtualPolynomialsBuilder,
};
use p3::field::Field;

pub fn i64_to_base<F: SmallField>(x: i64) -> F {
    if x >= 0 {
        F::from_u64(x as u64)
    } else {
        -F::from_u64((-x) as u64)
    }
}

pub fn split_to_u8<T: From<u8>>(value: u32) -> Vec<T> {
    (0..(u32::BITS / 8))
        .scan(value, |acc, _| {
            let limb = ((*acc & 0xFF) as u8).into();
            *acc >>= 8;
            Some(limb)
        })
        .collect_vec()
}

/// Compile time evaluated minimum function
/// returns min(a, b)
pub(crate) const fn const_min(a: usize, b: usize) -> usize {
    if a <= b { a } else { b }
}

/// Assumes each limb < max_value
/// adds 1 to the big value, while preserving the above constraint
pub(crate) fn add_one_to_big_num<F: Field>(limb_modulo: F, limbs: &[F]) -> Vec<F> {
    let mut should_add_one = true;
    let mut result = vec![];

    for limb in limbs {
        let mut new_limb_value = *limb;
        if should_add_one {
            new_limb_value += F::ONE;
            if new_limb_value == limb_modulo {
                new_limb_value = F::ZERO;
            } else {
                should_add_one = false;
            }
        }
        result.push(new_limb_value);
    }

    result
}

// split single u64 value into W slices, each slice got C bits.
// all the rest slices will be filled with 0 if W x C > 64
pub fn u64vec<const W: usize, const C: usize>(x: u64) -> [u64; W] {
    assert!(C <= 64);
    let mut x = x;
    let mut ret = [0; W];
    for ret in ret.iter_mut() {
        *ret = x & ((1 << C) - 1);
        x >>= C;
    }
    ret
}

/// TODO this is copy from gkr crate
/// including gkr crate after gkr clippy fix
///
/// This is to compute a variant of eq(\mathbf{x}, \mathbf{y}) for indices in
/// [0..=max_idx]. Specifically, it is an MLE of the following vector:
///     partial_eq_{\mathbf{x}}(\mathbf{y})
///         = \sum_{\mathbf{b}=0}^{max_idx} \prod_{i=0}^{n-1} (x_i y_i b_i + (1 - x_i)(1 - y_i)(1 - b_i))
pub(crate) fn eq_eval_less_or_equal_than<E: ExtensionField>(max_idx: usize, a: &[E], b: &[E]) -> E {
    assert!(a.len() >= b.len());
    // Compute running product of ( x_i y_i + (1 - x_i)(1 - y_i) )_{0 <= i <= n}
    let running_product = {
        let mut running_product = Vec::with_capacity(b.len() + 1);
        running_product.push(E::ONE);
        for i in 0..b.len() {
            let x = running_product[i] * (a[i] * b[i] + (E::ONE - a[i]) * (E::ONE - b[i]));
            running_product.push(x);
        }
        running_product
    };

    let running_product2 = {
        let mut running_product = vec![E::ZERO; b.len() + 1];
        running_product[b.len()] = E::ONE;
        for i in (0..b.len()).rev() {
            let bit = E::from_u64(((max_idx >> i) & 1) as u64);
            running_product[i] = running_product[i + 1]
                * (a[i] * b[i] * bit + (E::ONE - a[i]) * (E::ONE - b[i]) * (E::ONE - bit));
        }
        running_product
    };

    // Here is an example of how this works:
    // Suppose max_idx = (110101)_2
    // Then ans = eq(a, b)
    //          - eq(11011, a[1..6], b[1..6])eq(a[0..1], b[0..1])
    //          - eq(111, a[3..6], b[3..6])eq(a[0..3], b[0..3])
    let mut ans = running_product[b.len()];
    for i in 0..b.len() {
        let bit = (max_idx >> i) & 1;
        if bit == 1 {
            continue;
        }
        ans -= running_product[i] * running_product2[i + 1] * a[i] * b[i];
    }
    for v in a.iter().skip(b.len()) {
        ans *= E::ONE - *v;
    }
    ans
}

/// evaluate MLE M(x0, x1, x2, ..., xn) address vector with it evaluation format
/// on r = [r0, r1, r2, ...rn] succinctly
/// where `M = descending * scaled * M' + offset`
/// offset, scaled, is constant, descending = +1/-1
/// and M' := [0, 1, 2, 3, ....2^n-1]
/// succinctly format of M'(r) = r0 + r1 * 2 + r2 * 2^2 + .... rn * 2^n
pub fn eval_wellform_address_vec<E: ExtensionField>(
    offset: u64,
    scaled: u64,
    r: &[E],
    descending: bool,
) -> E {
    let (offset, scaled) = (E::from_u64(offset), E::from_u64(scaled));
    let tmp = scaled
        * r.iter()
            .scan(E::ONE, |state, x| {
                let result = *x * *state;
                *state *= E::from_u64(2); // Update the state for the next power of 2
                Some(result)
            })
            .sum::<E>();
    let tmp = if descending { tmp.neg() } else { tmp };
    offset + tmp
}

pub fn display_hashmap<K: Display, V: Display>(map: &HashMap<K, V>) -> String {
    format!(
        "[{}]",
        map.iter().map(|(k, v)| format!("{k}: {v}")).join(",")
    )
}

pub fn merge_frequency_tables<K: Hash + std::cmp::Eq>(
    lhs: HashMap<K, usize>,
    rhs: HashMap<K, usize>,
) -> HashMap<K, usize> {
    let mut ret = lhs;
    rhs.into_iter().for_each(|(key, value)| {
        *ret.entry(key).or_insert(0) += value;
    });
    ret
}

/// Temporarily override the panic hook
///
/// We restore the original hook after we are done.
pub fn with_panic_hook<F, R>(
    hook: Box<dyn Fn(&PanicHookInfo<'_>) + Sync + Send + 'static>,
    f: F,
) -> R
where
    F: FnOnce() -> R,
{
    // Save the current panic hook
    let original_hook = panic::take_hook();

    // Set the new panic hook
    panic::set_hook(hook);

    let result = f();

    // Restore the original panic hook
    panic::set_hook(original_hook);

    result
}

/// add mle terms into virtual poly by expression
/// return distinct witin in set
pub fn add_mle_list_by_expr<'a, E: ExtensionField>(
    expr_builder: &mut VirtualPolynomialsBuilder<'a, E>,
    exprs: &mut Vec<Expression<E>>,
    selector: Option<&'a MultilinearExtension<'a, E>>,
    wit_ins: Vec<&'a ArcMultilinearExtension<'a, E>>,
    expr: &Expression<E>,
    challenges: &[E],
    // sumcheck batch challenge
    alpha: E,
) -> BTreeSet<u16> {
    assert!(expr.is_monomial_form());
    let monomial_terms = expr.evaluate(
        &|_| unreachable!(),
        &|witness_id| vec![(E::ONE, { vec![witness_id] })],
        &|structural_witness_id, _, _, _| vec![(E::ONE, { vec![structural_witness_id] })],
        &|scalar| {
            vec![(scalar.map_either(E::from, |scalar| scalar).into_inner(), {
                vec![]
            })]
        },
        &|challenge_id, pow, scalar, offset| {
            let challenge = challenges[challenge_id as usize];
            vec![(challenge.exp_u64(pow as u64) * scalar + offset, vec![])]
        },
        &|mut a, b| {
            a.extend(b);
            a
        },
        &|mut a, mut b| {
            assert!(a.len() <= 2);
            assert!(b.len() <= 2);
            // special logic to deal with scaledsum
            // scaledsum second parameter must be 0
            if a.len() == 2 {
                assert!((a[1].0, a[1].1.is_empty()) == (E::ZERO, true));
                a.truncate(1);
            }
            if b.len() == 2 {
                assert!((b[1].0, b[1].1.is_empty()) == (E::ZERO, true));
                b.truncate(1);
            }

            a[0].1.extend(mem::take(&mut b[0].1));
            // return [ab]
            vec![(a[0].0 * b[0].0, mem::take(&mut a[0].1))]
        },
        &|mut x, a, b| {
            assert!(a.len() == 1 && a[0].1.is_empty()); // for challenge or constant, term should be empty
            assert!(b.len() == 1 && b[0].1.is_empty()); // for challenge or constant, term should be empty
            assert!(x.len() == 1 && (x[0].0, x[0].1.len()) == (E::ONE, 1)); // witin size only 1
            if b[0].0 == E::ZERO {
                // only include first term if b = 0
                vec![(a[0].0, mem::take(&mut x[0].1))]
            } else {
                // return [ax, b]
                vec![(a[0].0, mem::take(&mut x[0].1)), (b[0].0, vec![])]
            }
        },
    );
    for (constant, monomial_term) in monomial_terms.iter() {
        if *constant != E::ZERO && monomial_term.is_empty() && selector.is_none() {
            todo!("make virtual poly support pure constant")
        }
        let sel = selector.map(|sel| expr_builder.lift(Either::Left(sel)));
        let terms_polys = monomial_term
            .iter()
            .map(|wit_id| expr_builder.lift(Either::Left(wit_ins[*wit_id as usize])))
            .collect_vec();
        exprs.push(
            sel.into_iter()
                .chain(terms_polys)
                .product::<Expression<E>>()
                * Expression::Constant(Either::Right(*constant * alpha)),
        );
    }

    monomial_terms
        .into_iter()
        .flat_map(|(_, monomial_term)| monomial_term.into_iter().collect_vec())
        .collect::<BTreeSet<u16>>()
}

#[cfg(all(feature = "jemalloc", unix, not(test)))]
pub fn print_allocated_bytes() {
    use tikv_jemalloc_ctl::{epoch, stats};

    // Advance the epoch to refresh the stats
    let e = epoch::mib().unwrap();
    e.advance().unwrap();

    // Read allocated bytes
    let allocated = stats::allocated::read().unwrap();
    tracing::info!("jemalloc total allocated bytes: {}", allocated);
}

#[cfg(test)]
mod tests {
    use ff_ext::GoldilocksExt2;
    use itertools::Itertools;
    use multilinear_extensions::{
        Expression, ToExpr,
        mle::{ArcMultilinearExtension, IntoMLE},
        virtual_polys::VirtualPolynomialsBuilder,
    };
    use p3::field::PrimeCharacteristicRing;

    use crate::{
        circuit_builder::{CircuitBuilder, ConstraintSystem},
        utils::add_mle_list_by_expr,
    };
    use p3::goldilocks::Goldilocks;

    #[test]
    fn test_add_mle_list_by_expr() {
        type E = GoldilocksExt2;
        type F = Goldilocks;
        let mut cs = ConstraintSystem::new(|| "test_root");
        let mut cb = CircuitBuilder::<E>::new(&mut cs);
        let x = cb.create_witin(|| "x");
        let y = cb.create_witin(|| "y");

        let wits_in: Vec<ArcMultilinearExtension<E>> = (0..cs.num_witin as usize)
            .map(|_| vec![F::from_u64(1)].into_mle().into())
            .collect();

        let mut expr_builder = VirtualPolynomialsBuilder::new(1, 0);
        let mut exprs = vec![];

        // 3xy + 2y
        let expr: Expression<E> = 3 * x.expr() * y.expr() + 2 * y.expr();

        let distrinct_zerocheck_terms_set = add_mle_list_by_expr(
            &mut expr_builder,
            &mut exprs,
            None,
            wits_in.iter().collect_vec(),
            &expr,
            &[],
            GoldilocksExt2::ONE,
        );
        assert!(distrinct_zerocheck_terms_set.len() == 2);
        assert!(
            expr_builder
                .to_virtual_polys(&[exprs.into_iter().sum::<Expression<E>>()], &[])
                .degree()
                == 2
        );

        // 3x^3
        let mut expr_builder = VirtualPolynomialsBuilder::new(1, 0);
        let mut exprs = vec![];
        let expr: Expression<E> = 3 * x.expr() * x.expr() * x.expr();
        let distrinct_zerocheck_terms_set = add_mle_list_by_expr(
            &mut expr_builder,
            &mut exprs,
            None,
            wits_in.iter().collect_vec(),
            &expr,
            &[],
            GoldilocksExt2::ONE,
        );
        assert!(distrinct_zerocheck_terms_set.len() == 1);
        assert!(
            expr_builder
                .to_virtual_polys(&[exprs.into_iter().sum::<Expression<E>>()], &[])
                .degree()
                == 3
        );
    }
}
