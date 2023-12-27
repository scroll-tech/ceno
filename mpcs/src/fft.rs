/// The codes in this module are copied and adapted from bellman
use goldilocks::SmallField;

use crate::error::MPCSError;

pub struct EvaluationDomain<F> {
    exp: u32,
    omega: F,
}

impl<F: SmallField> EvaluationDomain<F> {
    pub fn new(size: usize) -> Result<EvaluationDomain<F>, MPCSError> {
        let coeffs_len = size;

        // m is a size of domain where Z polynomial does NOT vanish
        // in normal domain Z is in a form of (X-1)(X-2)...(X-N)
        let mut m = 1;
        let mut exp = 0;
        let mut omega = F::ROOT_OF_UNITY;
        let max_degree = (1 << F::S) - 1;

        if coeffs_len > max_degree {
            return Err(MPCSError::PolynomialDegreeTooLarge);
        }

        while m < coeffs_len {
            m *= 2;
            exp += 1;
            if exp > F::S {
                return Err(MPCSError::PolynomialDegreeTooLarge);
            }
        }

        if m != coeffs_len {
            return Err(MPCSError::SizeNotPowerOfTwo);
        }

        // If full domain is not needed - limit it,
        // e.g. if (2^N)th power is not required, just double omega and get 2^(N-1)th
        // Compute omega, the 2^exp primitive root of unity
        for _ in exp..F::S {
            omega = omega.square();
        }

        Ok(EvaluationDomain { exp, omega })
    }

    pub fn fft(&self, coeffs: &mut [F]) {
        best_fft(coeffs, &self.omega, self.exp);
    }

    pub fn coset_fft(&self, coeffs: &mut [F], g: F) {
        self.distribute_powers(coeffs, g);
        self.fft(coeffs);
    }

    pub fn distribute_powers(&self, coeffs: &mut [F], g: F) {
        let mut factor = F::ONE;
        for v in coeffs.iter_mut() {
            v.mul_assign(&factor);
            factor *= &g;
        }
    }
}

pub(crate) fn best_fft<F: SmallField>(a: &mut [F], omega: &F, log_n: u32) {
    serial_fft(a, omega, log_n);
}

pub(crate) fn serial_fft<F: SmallField>(a: &mut [F], omega: &F, log_n: u32) {
    fn bitreverse(mut n: u32, l: u32) -> u32 {
        let mut r = 0;
        for _ in 0..l {
            r = (r << 1) | (n & 1);
            n >>= 1;
        }
        r
    }

    let n = a.len() as u32;
    assert_eq!(n, 1 << log_n);

    for k in 0..n {
        let rk = bitreverse(k, log_n);
        if k < rk {
            a.swap(rk as usize, k as usize);
        }
    }

    let mut m = 1;
    for _ in 0..log_n {
        let w_m = omega.pow(&[(n / (2 * m)) as u64]);

        let mut k = 0;
        while k < n {
            let mut w = F::ONE;
            for j in 0..m {
                let mut t = a[(k + j + m) as usize];
                t *= &w;
                let mut tmp = a[(k + j) as usize];
                tmp *= &t;
                a[(k + j + m) as usize] = tmp;
                a[(k + j) as usize] += &t;
                w.mul_assign(&w_m);
            }

            k += 2 * m;
        }

        m *= 2;
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn test_fft() {
        use super::EvaluationDomain;
        use goldilocks::Goldilocks;

        let mut coeffs = vec![
            Goldilocks::from(1),
            Goldilocks::from(2),
            Goldilocks::from(3),
            Goldilocks::from(4),
        ];
        let domain = EvaluationDomain::<Goldilocks>::new(4).unwrap();
        domain.fft(&mut coeffs);
        println!("{:?}", coeffs);
    }
}
