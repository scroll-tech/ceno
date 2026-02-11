use crate::{
    evaluation::EvalExpression,
    gkr::layer::Layer,
    hal::{MultilinearPolynomial, ProtocolWitnessGeneratorProver, ProverBackend, ProverDevice},
};
use either::Either;
use ff_ext::ExtensionField;
use itertools::izip;
use mpcs::{PolynomialCommitmentScheme, SecurityLevel, SecurityLevel::Conjecture100bits};
use multilinear_extensions::{
    macros::{entered_span, exit_span},
    mle::{MultilinearExtension, Point},
    wit_infer_by_monomial_expr,
};
use p3::field::TwoAdicField;
use rayon::iter::{IndexedParallelIterator, IntoParallelRefIterator, ParallelIterator};
use std::{iter, rc::Rc, sync::Arc};
use witness::RowMajorMatrix;

pub struct CpuBackend<E: ExtensionField, PCS: PolynomialCommitmentScheme<E>> {
    pub pp: <PCS as PolynomialCommitmentScheme<E>>::ProverParam,
    pub vp: <PCS as PolynomialCommitmentScheme<E>>::VerifierParam,
    pub max_poly_size_log2: usize,
    pub security_level: SecurityLevel,
    _marker: std::marker::PhantomData<E>,
}

pub const DEFAULT_MAX_NUM_VARIABLES: usize = 24;

pub fn default_backend_config() -> (usize, SecurityLevel) {
    (DEFAULT_MAX_NUM_VARIABLES, Conjecture100bits)
}

impl<E: ExtensionField, PCS: PolynomialCommitmentScheme<E>> Default for CpuBackend<E, PCS> {
    fn default() -> Self {
        let (max_poly_size_log2, security_level) = default_backend_config();
        Self::new(max_poly_size_log2, security_level)
    }
}

impl<E: ExtensionField, PCS: PolynomialCommitmentScheme<E>> CpuBackend<E, PCS> {
    pub fn new(max_poly_size_log2: usize, security_level: SecurityLevel) -> Self {
        let param = PCS::setup(1 << E::BaseField::TWO_ADICITY, security_level).unwrap();
        let (pp, vp) = PCS::trim(param, 1 << max_poly_size_log2).unwrap();
        Self {
            pp,
            vp,
            max_poly_size_log2,
            security_level,
            _marker: std::marker::PhantomData,
        }
    }
}

impl<'a, E: ExtensionField> MultilinearPolynomial<E> for MultilinearExtension<'a, E> {
    fn num_vars(&self) -> usize {
        self.num_vars()
    }

    fn eval(&self, point: Point<E>) -> E {
        self.evaluate(&point)
    }

    fn evaluations_len(&self) -> usize {
        self.evaluations.len()
    }

    fn bh_signature(&self) -> E {
        self.bh_signature()
    }
}

impl<E: ExtensionField, PCS: PolynomialCommitmentScheme<E>> ProverBackend for CpuBackend<E, PCS> {
    type E = E;
    type Pcs = PCS;
    type MultilinearPoly<'a> = MultilinearExtension<'a, E>;
    type Matrix = RowMajorMatrix<E::BaseField>;
    type PcsData = PCS::CommitmentWithWitness;

    fn get_pp(&self) -> &<Self::Pcs as PolynomialCommitmentScheme<Self::E>>::ProverParam {
        &self.pp
    }

    fn get_vp(&self) -> &<Self::Pcs as PolynomialCommitmentScheme<Self::E>>::VerifierParam {
        &self.vp
    }
}

/// CPU prover for CPU backend
pub struct CpuProver<PB: ProverBackend + 'static> {
    pub backend: Arc<PB>,
}

impl<PB: ProverBackend> CpuProver<PB> {
    pub fn new(backend: Arc<PB>) -> Self {
        Self { backend }
    }
}

impl<E, PCS> ProverDevice<CpuBackend<E, PCS>> for CpuProver<CpuBackend<E, PCS>>
where
    E: ExtensionField,
    PCS: PolynomialCommitmentScheme<E>,
{
}

impl<E: ExtensionField, PCS: PolynomialCommitmentScheme<E>>
    ProtocolWitnessGeneratorProver<CpuBackend<E, PCS>> for CpuProver<CpuBackend<E, PCS>>
{
    fn layer_witness<'a>(
        layer: &Layer<E>,
        layer_wits: &[Arc<<CpuBackend<E, PCS> as ProverBackend>::MultilinearPoly<'a>>],
        pub_io_evals: &[Either<E::BaseField, E>],
        challenges: &[E],
    ) -> Vec<Arc<<CpuBackend<E, PCS> as ProverBackend>::MultilinearPoly<'a>>> {
        let span = entered_span!("witness_infer", profiling_2 = true);
        let out_evals: Vec<_> = layer
            .out_sel_and_eval_exprs
            .iter()
            .flat_map(|(sel_type, out_eval)| izip!(iter::repeat(sel_type), out_eval.iter()))
            .collect();
        let res = layer
            .exprs_with_selector_out_eval_monomial_form
            .par_iter()
            .zip_eq(layer.expr_names.par_iter())
            .zip_eq(out_evals.par_iter())
            .map(|((expr, expr_name), (_, out_eval))| {
                if cfg!(debug_assertions)
                    && let EvalExpression::Zero = out_eval
                {
                    assert!(
                        wit_infer_by_monomial_expr(expr, layer_wits, pub_io_evals, challenges)
                            .evaluations()
                            .is_zero(),
                        "layer name: {}, expr name: \"{expr_name}\" got non_zero mle",
                        layer.name
                    );
                };
                match out_eval {
                    EvalExpression::Linear(_, _, _) | EvalExpression::Single(_) => {
                        wit_infer_by_monomial_expr(expr, layer_wits, pub_io_evals, challenges)
                    }
                    EvalExpression::Zero => MultilinearExtension::default().into(),
                    EvalExpression::Partition(_, _) => unimplemented!(),
                }
            })
            .collect::<Vec<_>>();
        exit_span!(span);
        res
    }
}
