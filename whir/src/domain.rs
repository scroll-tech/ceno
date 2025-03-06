use ff_ext::ExtensionField;
use p3_commit::TwoAdicMultiplicativeCoset;

#[derive(Debug, Clone)]
pub struct Domain<E>
where
    E: ExtensionField,
{
    pub base_domain: Option<TwoAdicMultiplicativeCoset<E::BaseField>>, // The domain (in the base
    // field) for the initial FFT
    pub backing_domain: TwoAdicMultiplicativeCoset<E>,
}

impl<E> Domain<E>
where
    E: ExtensionField,
{
    pub fn new(degree: usize, log_rho_inv: usize) -> Option<Self> {
        let size = degree * (1 << log_rho_inv);
        let base_domain = TwoAdicMultiplicativeCoset::new(size)?;
        let backing_domain = Self::to_extension_domain(&base_domain);

        Some(Self {
            backing_domain,
            base_domain: Some(base_domain),
        })
    }

    // returns the size of the domain after folding folding_factor many times.
    //
    // This asserts that the domain size is divisible by 1 << folding_factor
    pub fn folded_size(&self, folding_factor: usize) -> usize {
        assert!(self.backing_domain.size() % (1 << folding_factor) == 0);
        self.backing_domain.size() / (1 << folding_factor)
    }

    pub fn size(&self) -> usize {
        self.backing_domain.size()
    }

    pub fn scale(&self, power: usize) -> Self {
        Self {
            backing_domain: self.scale_generator_by(power),
            base_domain: None, // Set to zero because we only care for the initial
        }
    }

    fn to_extension_domain(
        domain: &TwoAdicMultiplicativeCoset<E::BaseField>,
    ) -> TwoAdicMultiplicativeCoset<E> {
        TwoAdicMultiplicativeCoset {
            log_n: domain.log_n,
            shift: E::from(domain.shift),
        }
    }

    // Takes the underlying backing_domain = <w>, and computes the new domain
    // <w^power> (note this will have size |L| / power)
    fn scale_generator_by(&self, power: usize) -> TwoAdicMultiplicativeCoset<E> {
        TwoAdicMultiplicativeCoset {
            log_n: self.backing_domain.log_n - p3_util::log2_strict_usize(power),
            shift: self.backing_domain.shift.exp_u64(power as u64),
        }
    }
}
