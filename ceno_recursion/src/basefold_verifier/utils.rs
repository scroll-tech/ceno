use openvm_native_compiler::ir::*;
use openvm_native_recursion::vars::HintSlice;
use p3::babybear::BabyBear;
use p3::field::FieldAlgebra;

use crate::basefold_verifier::mmcs::MmcsProof;

// XXX: more efficient pow implementation
pub fn pow<C: Config>(builder: &mut Builder<C>, base: Var<C::N>, exponent: Var<C::N>) -> Var<C::N> {
    let value: Var<C::N> = builder.constant(C::N::ONE);
    builder.range(0, exponent).for_each(|_, builder| {
        builder.assign(&value, value * base);
    });
    value
}

// XXX: more efficient pow implementation
pub fn pow_felt<C: Config>(
    builder: &mut Builder<C>,
    base: Felt<C::F>,
    exponent: Var<C::N>,
) -> Felt<C::F> {
    let value: Felt<C::F> = builder.constant(C::F::ONE);
    builder.range(0, exponent).for_each(|_, builder| {
        builder.assign(&value, value * base);
    });
    value
}

// XXX: more efficient pow implementation
pub fn pow_felt_bits<C: Config>(
    builder: &mut Builder<C>,
    base: Felt<C::F>,
    exponent_bits: &Array<C, Var<C::N>>,
    exponent_len: Usize<C::N>, // This is not exponent_bits.len(), possibly smaller than it
) -> Felt<C::F> {
    let value: Felt<C::F> = builder.constant(C::F::ONE);

    // Little endian
    // let repeated_squared: Felt<C::F> = base;
    // builder.range(0, exponent_len).for_each(|ptr, builder| {
    //     let ptr = ptr[0];
    //     let bit = builder.get(exponent_bits, ptr);
    //     builder.if_eq(bit, C::N::ONE).then(|builder| {
    //         builder.assign(&value, value * repeated_squared);
    //     });
    //     builder.assign(&repeated_squared, repeated_squared * repeated_squared);
    // });

    // Big endian
    builder.range(0, exponent_len).for_each(|ptr, builder| {
        let ptr = ptr[0];
        builder.assign(&value, value * value);
        let bit = builder.get(exponent_bits, ptr);
        builder.if_eq(bit, C::N::ONE).then(|builder| {
            builder.assign(&value, value * base);
        });
    });
    value
}

pub fn pow_2<C: Config>(builder: &mut Builder<C>, exponent: Var<C::N>) -> Var<C::N> {
    let two: Var<C::N> = builder.constant(C::N::from_canonical_usize(2));
    pow(builder, two, exponent)
}

// XXX: Equally outrageously inefficient
pub fn next_power_of_two<C: Config>(builder: &mut Builder<C>, value: Var<C::N>) -> Var<C::N> {
    // Non-deterministically supply the exponent n such that
    // 2^n < v <= 2^{n+1}
    // Ignore if v == 1
    let n: Var<C::N> = builder.hint_var();
    let ret = pow_2(builder, n);
    builder.if_eq(value, Usize::from(1)).then(|builder| {
        builder.assign(&ret, Usize::from(1));
    });
    builder.if_ne(value, Usize::from(1)).then(|builder| {
        builder.assert_less_than_slow_bit_decomp(ret, value);
        let two: Var<C::N> = builder.constant(C::N::from_canonical_usize(2));
        builder.assign(&ret, ret * two);
        let ret_plus_one = builder.eval(ret.clone() + Usize::from(1));
        builder.assert_less_than_slow_bit_decomp(value, ret_plus_one);
    });
    ret
}

// Dot product: li * ri
pub fn dot_product<C: Config, F>(
    builder: &mut Builder<C>,
    li: &Array<C, Ext<C::F, C::EF>>,
    ri: &Array<C, F>,
) -> Ext<C::F, C::EF>
where
    F: openvm_native_compiler::ir::MemVariable<C> + 'static,
{
    dot_product_with_index::<C, F>(builder, li, ri, Usize::from(0), Usize::from(0), li.len())
}

// Generic dot product of li[llo..llo+len] * ri[rlo..rlo+len]
pub fn dot_product_with_index<C: Config, F>(
    builder: &mut Builder<C>,
    li: &Array<C, Ext<C::F, C::EF>>,
    ri: &Array<C, F>,
    llo: Usize<C::N>,
    rlo: Usize<C::N>,
    len: Usize<C::N>,
) -> Ext<C::F, C::EF>
where
    F: openvm_native_compiler::ir::MemVariable<C> + 'static,
{
    let ret: Ext<C::F, C::EF> = builder.constant(C::EF::ZERO);

    builder.range(0, len).for_each(|i_vec, builder| {
        let i = i_vec[0];
        let lidx: Var<C::N> = builder.eval(llo.clone() + i);
        let ridx: Var<C::N> = builder.eval(rlo.clone() + i);
        let l = builder.get(li, lidx);
        let r = builder.get(ri, ridx);
        builder.assign(&ret, ret + l * r);
    });
    ret
}

// Convert the first len entries of binary to decimal
// BIN is in big endian
pub fn bin_to_dec<C: Config>(
    builder: &mut Builder<C>,
    bin: &Array<C, Var<C::N>>,
    len: Var<C::N>,
) -> Var<C::N> {
    let value: Var<C::N> = builder.constant(C::N::ZERO);
    let two: Var<C::N> = builder.constant(C::N::TWO);
    builder.range(0, len).for_each(|i_vec, builder| {
        let i = i_vec[0];
        builder.assign(&value, value * two);
        let next_bit = builder.get(bin, i);
        builder.assign(&value, value + next_bit);
    });
    value
}

// Convert start to end entries of binary to decimal in little endian
pub fn bin_to_dec_le<C: Config>(
    builder: &mut Builder<C>,
    bin: &Array<C, Var<C::N>>,
    start: Var<C::N>,
    end: Var<C::N>,
) -> Var<C::N> {
    let value: Var<C::N> = builder.constant(C::N::ZERO);
    let two: Var<C::N> = builder.constant(C::N::TWO);
    let power_of_two: Var<C::N> = builder.constant(C::N::ONE);
    builder.range(start, end).for_each(|i_vec, builder| {
        let i = i_vec[0];
        let next_bit = builder.get(bin, i);
        builder.assign(&value, value + power_of_two * next_bit);
        builder.assign(&power_of_two, power_of_two * two);
    });
    value
}

// Sort a list in decreasing order, returns:
// 1. The original index of each sorted entry
// 2. Number of unique entries
// 3. Number of counts of each unique entry
pub fn sort_with_count<C: Config, E, N, Ind>(
    builder: &mut Builder<C>,
    list: &Array<C, E>,
    ind: Ind, // Convert loaded out entries into comparable ones
) -> (
    Array<C, Var<C::N>>,
    Var<C::N>,
    Array<C, Var<C::N>>,
    Array<C, Var<C::N>>,
)
where
    E: openvm_native_compiler::ir::MemVariable<C>,
    N: Into<SymbolicVar<<C as openvm_native_compiler::ir::Config>::N>>
        + openvm_native_compiler::ir::Variable<C>,
    Ind: Fn(E) -> N,
{
    let len = list.len();
    // Nondeterministically supplies:
    // 1. num_unique_entries: number of different entries
    // 2. entry_order: after sorting by decreasing order, the original index of each entry
    // To ensure that entry_order represents sorted index, assert that
    // 1. It has the same length as list (checked by requesting list.len() hints)
    // 2. It does not contain the same index twice (checked via a correspondence array)
    // 3. Sorted entries are in decreasing order
    // While checking, record:
    // 1. count_per_unique_entry: for each unique entry value, count of entries of that value
    let num_unique_entries = builder.hint_var();
    let count_per_unique_entry = builder.dyn_array(num_unique_entries);
    let sorted_unique_num_vars = builder.dyn_array(num_unique_entries);
    let zero: Ext<C::F, C::EF> = builder.constant(C::EF::ZERO);
    let one: Ext<C::F, C::EF> = builder.constant(C::EF::ONE);
    let entries_sort_surjective: Array<C, Ext<C::F, C::EF>> = builder.dyn_array(len.clone());
    builder.range(0, len.clone()).for_each(|i_vec, builder| {
        let i = i_vec[0];
        builder.set(&entries_sort_surjective, i, zero.clone());
    });

    let entries_order = builder.dyn_array(len.clone());
    let next_order = builder.hint_var();
    // Check surjection
    let surjective = builder.get(&entries_sort_surjective, next_order);
    builder.assert_ext_eq(surjective, zero.clone());
    builder.set(&entries_sort_surjective, next_order, one.clone());
    builder.set_value(&entries_order, 0, next_order);
    let last_entry = ind(builder.get(&list, next_order));

    let last_unique_entry_index: Var<C::N> = builder.eval(Usize::from(0));
    let last_count_per_unique_entry: Var<C::N> = builder.eval(Usize::from(1));
    builder.range(1, len).for_each(|i_vec, builder| {
        let i = i_vec[0];
        let next_order = builder.hint_var();
        // Check surjection
        let surjective = builder.get(&entries_sort_surjective, next_order);
        builder.assert_ext_eq(surjective, zero.clone());
        builder.set(&entries_sort_surjective, next_order, one.clone());
        // Check entries
        let next_entry = ind(builder.get(&list, next_order));
        builder
            .if_eq(last_entry.clone(), next_entry.clone())
            .then(|builder| {
                // next_entry == last_entry
                builder.assign(
                    &last_count_per_unique_entry,
                    last_count_per_unique_entry + Usize::from(1),
                );
            });
        builder
            .if_ne(last_entry.clone(), next_entry.clone())
            .then(|builder| {
                // next_entry < last_entry
                builder.assert_less_than_slow_small_rhs(next_entry.clone(), last_entry.clone());

                // Update count_per_unique_entry
                builder.set(
                    &count_per_unique_entry,
                    last_unique_entry_index,
                    last_count_per_unique_entry,
                );
                builder.set(
                    &sorted_unique_num_vars,
                    last_unique_entry_index,
                    last_entry.clone(),
                );
                builder.assign(&last_entry, next_entry.clone());
                builder.assign(
                    &last_unique_entry_index,
                    last_unique_entry_index + Usize::from(1),
                );
                builder.assign(&last_count_per_unique_entry, Usize::from(1));
            });

        builder.set_value(&entries_order, i, next_order);
    });

    // Final check on num_unique_entries and count_per_unique_entry
    builder.set(
        &count_per_unique_entry,
        last_unique_entry_index,
        last_count_per_unique_entry,
    );
    builder.set(
        &sorted_unique_num_vars,
        last_unique_entry_index,
        last_entry.clone(),
    );
    builder.assign(
        &last_unique_entry_index,
        last_unique_entry_index + Usize::from(1),
    );
    builder.assert_var_eq(last_unique_entry_index, num_unique_entries);

    (
        entries_order,
        num_unique_entries,
        count_per_unique_entry,
        sorted_unique_num_vars,
    )
}

pub fn codeword_fold_with_challenge<C: Config>(
    builder: &mut Builder<C>,
    left: Ext<C::F, C::EF>,
    right: Ext<C::F, C::EF>,
    challenge: Ext<C::F, C::EF>,
    coeff: Felt<C::F>,
    inv_2: Felt<C::F>,
) -> Ext<C::F, C::EF> {
    // original (left, right) = (lo + hi*x, lo - hi*x), lo, hi are codeword, but after times x it's not codeword
    // recover left & right codeword via (lo, hi) = ((left + right) / 2, (left - right) / 2x)
    let lo: Ext<C::F, C::EF> = builder.eval((left + right) * inv_2);
    let hi: Ext<C::F, C::EF> = builder.eval((left - right) * coeff);
    // e.g. coeff = (2 * dit_butterfly)^(-1) in rs code
    // we do fold on (lo, hi) to get folded = (1-r) * lo + r * hi
    // (with lo, hi are two codewords), as it match perfectly with raw message in
    // lagrange domain fixed variable
    let ret: Ext<C::F, C::EF> = builder.eval(lo + challenge * (hi - lo));
    ret
}

pub(crate) fn read_hint_slice<C: Config>(builder: &mut Builder<C>) -> HintSlice<C> {
    let length = Usize::from(builder.hint_var());
    let id = Usize::from(builder.hint_load());
    HintSlice { length, id }
}

pub(crate) fn write_mmcs_proof(proof: &MmcsProof) -> Vec<Vec<BabyBear>> {
    vec![
        vec![BabyBear::from_canonical_usize(proof.len())],
        proof.iter().flatten().copied().collect::<Vec<_>>(),
    ]
}
