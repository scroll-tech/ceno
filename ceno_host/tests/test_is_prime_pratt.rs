use mod_exp::mod_exp;
use prime_factorization::Factorization;
use std::{
    collections::{BTreeMap, BTreeSet},
    iter::once,
};

type PrattCertificate = BTreeMap<u64, Vec<u64>>;

// fn pratt(n: u128) {
//   // `factor_repr` is now an instance of the `Factorization` struct
//   let factor_repr = Factorization::run(n);
//   println!("{} = {}", n, factor_repr);
//   // let x = factor_repr.factors;
// }

// #[test]
// fn test_pratt() {
//   pratt(1997);
// }

/// Generate a Pratt primality certificate for `n`.
/// Returns None if `n <= 1` or if any part of the process fails.
fn generate_pratt_certificate(n: u64) -> Option<PrattCertificate> {
    if n <= 1 {
        return None; // No certificate for n <= 1
    }

    let mut certificate = BTreeMap::new();
    if n == 2 {
        certificate.insert(2, vec![]); // Base case: 2 is prime
        return Some(certificate);
    }

    let mut stack: BTreeSet<_> = once(n).collect();
    while let Some(current) = stack.pop_last() {
        if current > 2 || !certificate.contains_key(&current) {
            let current_minus_1 = current - 1;
            let factors = Factorization::run(current_minus_1);
            let primes: Vec<u64> = factors.factors;

            // Add the current number and its factors to the certificate
            certificate.insert(current, primes.clone());

            // Add any new factors to the stack for processing
            for prime in primes {
                stack.insert(prime);
            }
        }
    }
    Some(certificate)
}

/// Verify a Pratt primality certificate.
/// Checks that all numbers in the certificate are prime.
/// An empty certificate is considered valid.
fn verify_pratt_certificate(certificate: &PrattCertificate) -> bool {
    for (&current, factors) in certificate {
        let current_minus_1 = current - 1;
        // Check that the product of the factors is equal to current - 1
        if current_minus_1 != factors.iter().product::<u64>() {
            return false;
        }
        // check that all factors are prime, ie they are in the certificate
        for &factor in factors {
            if !certificate.contains_key(&factor) {
                return false;
            }
        }
        // Check that all factors divide current - 1
        // TODO: only check the unique factors?
        for &factor in factors {
            // TODO: I'm not sure if that should be == 1 or != 1?
            // Check Fermat's little theorem
            if mod_exp(factor, current_minus_1 / factor, current) != 1 {
                return false; // Fermat's little theorem failed
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
        fn test_generate_and_verify_pratt_certificate(n in 2u64..1000) {
            if let Some(certificate) = generate_pratt_certificate(n) {
                assert!(verify_pratt_certificate(&certificate), "Failed to verify certificate for {n}");
            } else {
                // If no certificate is generated, n is not prime
                assert!(!Factorization::run(n).is_prime);
            }
        }
    }

    /// Test: empty certificate is valid.
    #[test]
    fn test_empty_certificate() {
        let empty_certificate: PrattCertificate = BTreeMap::new();
        assert!(verify_pratt_certificate(&empty_certificate));
    }

    /// Test: manually validate a certificate for a small prime number (e.g., 7).
    #[test]
    fn test_manual_certificate() {
        let mut certificate = PrattCertificate::new();
        certificate.insert(7, vec![2, 3]);
        certificate.insert(2, vec![]);
        certificate.insert(3, vec![2]);
        assert!(verify_pratt_certificate(&certificate));
    }

    /// Test: manually validate a certificate for a non-prime number (e.g., 9).
    #[test]
    fn test_invalid_certificate() {
        let mut certificate = PrattCertificate::new();
        certificate.insert(9, vec![3]); // Missing full prime factorization of 8
        certificate.insert(3, vec![2]);
        assert!(!verify_pratt_certificate(&certificate));
    }
}
