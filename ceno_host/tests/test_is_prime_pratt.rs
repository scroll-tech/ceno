use mod_exp::mod_exp;
use prime_factorization::Factorization;
use std::collections::{BTreeMap, BTreeSet};

type PrattCertificate = BTreeMap<u128, (u128, Vec<u128>)>;

/// Generate a Pratt primality certificate for `n`.
/// Returns None if `n <= 1` or if any part of the process fails.
fn generate_pratt_certificate(n: u128) -> PrattCertificate {
    let mut certificate = BTreeMap::new();

    let factors = Factorization::run(n).factors;

    let mut stack: BTreeSet<_> = factors.into_iter().collect();
    while let Some(current) = stack.pop_last() {
        if current > 2 && !certificate.contains_key(&current) {
            let current_minus_1 = current - 1;
            let factors = Factorization::run(current_minus_1);
            let primes: Vec<u128> = factors.factors;

            // Add the current number and its factors to the certificate
            for a in 2..current {
                println!("a: {a}");
                // Just arbitrarily, try at most 100 numbers to avoid an infinite loop.
                assert!(a < 100);
                if mod_exp(a, current_minus_1, current) == 1
                  && primes.iter().all(|&p| mod_exp(a, current_minus_1 / p, current) != 1) {
                    certificate.insert(current, (a, primes.clone()));
                    break;
                }
            }


            // Add any new factors to the stack for processing
            for prime in primes {
                stack.insert(prime);
            }
        }
    }
    certificate
}

/// Verify a Pratt primality certificate.
/// Checks that all numbers in the certificate are prime.
/// An empty certificate is considered valid.
fn verify_pratt_certificate(certificate: &PrattCertificate) -> bool {
    for (&current, (witness, factors)) in certificate {
        let current_minus_1 = current - 1;
        // Check that the product of the factors is equal to current - 1
        if current_minus_1 != factors.iter().product::<u128>() {
            println!("not product; current_minus_1: {current_minus_1}, factors: {factors:?}");
            return false;
        }
        // check that all factors are prime, ie they are in the certificate
        for &factor in factors {
            if factor != 2 && !certificate.contains_key(&factor) {
                println!("not contained; factor: {factor}, factors: {factors:?}");
                return false;
            }
        }
        let &a = witness;
        // Check Fermat's little theorem for the product
        let res = mod_exp(a, current_minus_1, current);
        if res != 1 {
            println!(
                "not fermat; current_minus_1: {current_minus_1}, current: {current}, res: {res}"
            );
            return false;
        }
        // Check that all factors divide current - 1
        // TODO: only check the unique factors?
        for &factor in factors {
            if factor > 2 {
                // TODO: I'm not sure if that should be == 1 or != 1?
                // Check Fermat's little theorem for the factors
                if mod_exp(a, current_minus_1 / factor, current) == 1 {
                    println!(
                        "not fermat factor; current_minus_1: {current_minus_1}, factor: {factor}, current: {current}, current_minus_1 / factor: {}",
                        current_minus_1 / factor
                    );
                    return false; // Fermat's little theorem failed
                }
            }
        }
    }

    true // All checks passed
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    // Property-based test: if a certificate is generated for a prime number, it should verify.
    proptest! {
        #[test]
        fn test_generate_and_verify_pratt_certificate(n in 2u128..u64::MAX as u128) {
            let certificate = generate_pratt_certificate(n);
            // if certificate.contains_key(&n) {
                assert!(verify_pratt_certificate(&certificate), "Failed to verify certificate for {n}: {certificate:?}");
            // } else {
                // assert!(n==2 || !Factorization::run(n).is_prime);
            // }
        }
    }

    #[test]
    fn test_example() {
        // let n = 43178;
        let n: u128 = 5897030988067222811;
        let certificate = generate_pratt_certificate(n);
        if certificate.contains_key(&n) {
            assert!(
                verify_pratt_certificate(&certificate),
                "Failed to verify certificate for {n}: {certificate:?}"
            );
        } else {
            assert!(n == 2 || !Factorization::run(n).is_prime);
        }
    }

    // /// Test: empty certificate is valid.
    // #[test]
    // fn test_empty_certificate() {
    //     let empty_certificate: PrattCertificate = BTreeMap::new();
    //     assert!(verify_pratt_certificate(&empty_certificate));
    // }

    // /// Test: manually validate a certificate for a small prime number (e.g., 7).
    // #[test]
    // fn test_manual_certificate() {
    //     let mut certificate = PrattCertificate::new();
    //     certificate.insert(7, vec![2, 3]);
    //     certificate.insert(2, vec![]);
    //     certificate.insert(3, vec![2]);
    //     assert!(verify_pratt_certificate(&certificate));
    // }

    // /// Test: manually validate a certificate for a non-prime number (e.g., 9).
    // #[test]
    // fn test_invalid_certificate() {
    //     let mut certificate = PrattCertificate::new();
    //     certificate.insert(9, vec![3]); // Missing full prime factorization of 8
    //     certificate.insert(3, vec![2]);
    //     assert!(!verify_pratt_certificate(&certificate));
    // }
}
