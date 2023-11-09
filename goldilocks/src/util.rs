use std::arch::asm;
use std::hint::unreachable_unchecked;

use ff::{Field, PrimeField};
use subtle::{Choice, ConditionallySelectable, ConstantTimeEq, CtOption};

use crate::fp::{Goldilocks, MODULUS};

#[inline(always)]
pub fn assume(p: bool) {
    debug_assert!(p);
    if !p {
        unsafe {
            unreachable_unchecked();
        }
    }
}

/// Try to force Rust to emit a branch. Example:
///     if x > 2 {
///         y = foo();
///         branch_hint();
///     } else {
///         y = bar();
///     }
/// This function has no semantics. It is a hint only.
#[inline(always)]
pub fn branch_hint() {
    unsafe {
        asm!("", options(nomem, nostack, preserves_flags));
    }
}

/// Fast addition modulo ORDER for x86-64.
/// This function is marked unsafe for the following reasons:
///   - It is only correct if x + y < 2**64 + ORDER = 0x1ffffffff00000001.
///   - It is only faster in some circumstances. In particular, on x86 it overwrites both inputs in
///     the registers, so its use is not recommended when either input will be used again.
#[inline(always)]
#[cfg(target_arch = "x86_64")]
pub(crate) unsafe fn add_no_canonicalize_trashing_input(x: u64, y: u64) -> u64 {
    let res_wrapped: u64;
    let adjustment: u64;
    asm!(
        "add {0}, {1}",
        // Trick. The carry flag is set iff the addition overflowed.
        // sbb x, y does x := x - y - CF. In our case, x and y are both {1:e}, so it simply does
        // {1:e} := 0xffffffff on overflow and {1:e} := 0 otherwise. {1:e} is the low 32 bits of
        // {1}; the high 32-bits are zeroed on write. In the end, we end up with 0xffffffff in {1}
        // on overflow; this happens be EPSILON.
        // Note that the CPU does not realize that the result of sbb x, x does not actually depend
        // on x. We must write the result to a register that we know to be ready. We have a
        // dependency on {1} anyway, so let's use it.
        "sbb {1:e}, {1:e}",
        inlateout(reg) x => res_wrapped,
        inlateout(reg) y => adjustment,
        options(pure, nomem, nostack),
    );
    assume(x != 0 || (res_wrapped == y && adjustment == 0));
    assume(y != 0 || (res_wrapped == x && adjustment == 0));
    // Add EPSILON == subtract ORDER.
    // Cannot overflow unless the assumption if x + y < 2**64 + ORDER is incorrect.
    res_wrapped + adjustment
}

#[inline(always)]
#[cfg(not(target_arch = "x86_64"))]
pub(crate) unsafe fn add_no_canonicalize_trashing_input(x: u64, y: u64) -> u64 {
    let (res_wrapped, carry) = x.overflowing_add(y);
    // Below cannot overflow unless the assumption if x + y < 2**64 + ORDER is incorrect.
    res_wrapped + EPSILON * (carry as u64)
}

#[inline]
pub(crate) fn split(x: u128) -> (u64, u64) {
    (x as u64, (x >> 64) as u64)
}

/// Try to invert an element in a prime field.
///
/// The algorithm below is the "plus-minus-inversion" method
/// with an "almost Montgomery inverse" flair. See Handbook of
/// Elliptic and Hyperelliptic Cryptography, Algorithms 11.6
/// and 11.12.
#[allow(clippy::many_single_char_names)]
pub(crate) fn try_inverse_u64(x: &u64) -> Option<u64> {
    let mut f = *x;
    let mut g = MODULUS;
    // NB: These two are very rarely such that their absolute
    // value exceeds (p-1)/2; we are paying the price of i128 for
    // the whole calculation, just for the times they do
    // though. Measurements suggest a further 10% time saving if c
    // and d could be replaced with i64's.
    let mut c = 1i128;
    let mut d = 0i128;

    if f == 0 {
        return None;
    }

    // f and g must always be odd.
    let mut k = f.trailing_zeros();
    f >>= k;
    if f == 1 {
        return Some(inverse_2exp(k as usize));
    }

    // The first two iterations are unrolled. This is to handle
    // the case where f and g are both large and f+g can
    // overflow. log2(max{f,g}) goes down by at least one each
    // iteration though, so after two iterations we can be sure
    // that f+g won't overflow.

    // Iteration 1:
    safe_iteration(&mut f, &mut g, &mut c, &mut d, &mut k);

    if f == 1 {
        // c must be -1 or 1 here.
        if c == -1 {
            return Some(MODULUS - inverse_2exp(k as usize));
        }
        debug_assert!(c == 1, "bug in try_inverse_u64");
        return Some(inverse_2exp(k as usize));
    }

    // Iteration 2:
    safe_iteration(&mut f, &mut g, &mut c, &mut d, &mut k);

    // Remaining iterations:
    while f != 1 {
        unsafe {
            unsafe_iteration(&mut f, &mut g, &mut c, &mut d, &mut k);
        }
    }

    // The following two loops adjust c so it's in the canonical range
    // [0, F::ORDER).

    // The maximum number of iterations observed here is 2; should
    // prove this.
    while c < 0 {
        c += MODULUS as i128;
    }

    // The maximum number of iterations observed here is 1; should
    // prove this.
    while c >= MODULUS as i128 {
        c -= MODULUS as i128;
    }

    // Precomputing the binary inverses rather than using inverse_2exp
    // saves ~5ns on my machine.
    let res = Goldilocks(c as u64) * Goldilocks(inverse_2exp(k as usize));
    debug_assert!(
        Goldilocks(*x) * res == Goldilocks::ONE,
        "bug in try_inverse_u64"
    );
    Some(res.0)
}

/// This is a 'safe' iteration for the modular inversion algorithm. It
/// is safe in the sense that it will produce the right answer even
/// when f + g >= 2^64.
#[inline(always)]
fn safe_iteration(f: &mut u64, g: &mut u64, c: &mut i128, d: &mut i128, k: &mut u32) {
    if f < g {
        std::mem::swap(f, g);
        std::mem::swap(c, d);
    }
    if *f & 3 == *g & 3 {
        // f - g = 0 (mod 4)
        *f -= *g;
        *c -= *d;

        // kk >= 2 because f is now 0 (mod 4).
        let kk = f.trailing_zeros();
        *f >>= kk;
        *d <<= kk;
        *k += kk;
    } else {
        // f + g = 0 (mod 4)
        *f = (*f >> 2) + (*g >> 2) + 1u64;
        *c += *d;
        let kk = f.trailing_zeros();
        *f >>= kk;
        *d <<= kk + 2;
        *k += kk + 2;
    }
}

/// This is an 'unsafe' iteration for the modular inversion
/// algorithm. It is unsafe in the sense that it might produce the
/// wrong answer if f + g >= 2^64.
#[inline(always)]
unsafe fn unsafe_iteration(f: &mut u64, g: &mut u64, c: &mut i128, d: &mut i128, k: &mut u32) {
    if *f < *g {
        std::mem::swap(f, g);
        std::mem::swap(c, d);
    }
    if *f & 3 == *g & 3 {
        // f - g = 0 (mod 4)
        *f -= *g;
        *c -= *d;
    } else {
        // f + g = 0 (mod 4)
        *f += *g;
        *c += *d;
    }

    // kk >= 2 because f is now 0 (mod 4).
    let kk = f.trailing_zeros();
    *f >>= kk;
    *d <<= kk;
    *k += kk;
}

/// Compute the inverse of 2^exp in this field.
#[inline]
fn inverse_2exp(exp: usize) -> u64 {
    // Let p = char(F). Since 2^exp is in the prime subfield, i.e. an
    // element of GF_p, its inverse must be as well. Thus we may add
    // multiples of p without changing the result. In particular,
    // 2^-exp = 2^-exp - p 2^-exp
    //        = 2^-exp (1 - p)
    //        = p - (p - 1) / 2^exp

    // If this field's two adicity, t, is at least exp, then 2^exp divides
    // p - 1, so this division can be done with a simple bit shift. If
    // exp > t, we repeatedly multiply by 2^-t and reduce exp until it's in
    // the right range.

    // NB: The only reason this is split into two cases is to save
    // the multiplication (and possible calculation of
    // inverse_2_pow_adicity) in the usual case that exp <=
    // TWO_ADICITY. Can remove the branch and simplify if that
    // saving isn't worth it.
    let res = if exp > 32 {
        // NB: This should be a compile-time constant
        // MODULUS - ((MODULUS - 1) >> 32)
        let inverse_2_pow_adicity = Goldilocks(0xfffffffe00000002);

        let mut res = inverse_2_pow_adicity;
        let mut e = exp - 32;

        while e > 32 {
            res *= inverse_2_pow_adicity;
            e -= 32;
        }
        res * Goldilocks(MODULUS - ((MODULUS - 1) >> e))
    } else {
        Goldilocks(MODULUS - ((MODULUS - 1) >> exp))
    };
    res.0
}

pub(crate) fn sqrt_tonelli_shanks(f: &Goldilocks, tm1d2: u64) -> CtOption<Goldilocks> {
    // w = self^((t - 1) // 2)
    let w = f.pow_vartime([tm1d2]);

    let mut v = Goldilocks::S;
    let mut x = w * f;
    let mut b = x * w;

    // Initialize z as the 2^S root of unity.
    let mut z = Goldilocks::ROOT_OF_UNITY;

    for max_v in (1..=Goldilocks::S).rev() {
        let mut k = 1;
        let mut tmp = b.square();
        let mut j_less_than_v: Choice = 1.into();

        for j in 2..max_v {
            let tmp_is_one = tmp.ct_eq(&Goldilocks::ONE);
            let squared = Goldilocks::conditional_select(&tmp, &z, tmp_is_one).square();
            tmp = Goldilocks::conditional_select(&squared, &tmp, tmp_is_one);
            let new_z = Goldilocks::conditional_select(&z, &squared, tmp_is_one);
            j_less_than_v &= !j.ct_eq(&v);
            k = u32::conditional_select(&j, &k, tmp_is_one);
            z = Goldilocks::conditional_select(&z, &new_z, j_less_than_v);
        }

        let result = x * z;
        x = Goldilocks::conditional_select(&result, &x, b.ct_eq(&Goldilocks::ONE));
        z = z.square();
        b *= z;
        v = k;
    }
    CtOption::new(
        x,
        (x * x).ct_eq(f), // Only return Some if it's the square root.
    )
}
