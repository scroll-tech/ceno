use ff_ext::ExtensionField;
use multilinear_extensions::virtual_poly_v2::ArcMultilinearExtension;
use serde::Serialize;
use sumcheck::structs::IOPProverMessage;

pub struct TowerProver;

#[derive(Clone, Serialize)]
pub struct TowerProofs<E: ExtensionField> {
    pub proofs: Vec<Vec<IOPProverMessage<E>>>,
    // specs -> layers -> evals
    pub prod_specs_eval: Vec<Vec<Vec<E>>>,
    // specs -> layers -> point
    #[serde(skip)] // verifier can derive points itself
    pub prod_specs_points: Vec<Vec<Point<E>>>,
    // specs -> layers -> evals
    pub logup_specs_eval: Vec<Vec<Vec<E>>>,
    // specs -> layers -> point
    #[serde(skip)] // verifier can derive points itself
    pub logup_specs_points: Vec<Vec<Point<E>>>,
}

pub struct TowerProverSpec<'a, E: ExtensionField> {
    pub witness: Vec<Vec<ArcMultilinearExtension<'a, E>>>,
}

pub type WitnessId = u16;
pub type ChallengeId = u16;

pub enum ROMType {
    U5,  // 2^5 = 32
    U16, // 2^16 = 65,536
}

#[derive(Clone, Debug, Copy)]
pub enum RAMType {
    GlobalState,
    Register,
}

/// A point is a vector of num_var length
pub type Point<F> = Vec<F>;

/// A point and the evaluation of this point.
#[derive(Clone, Debug, PartialEq)]
pub struct PointAndEval<F> {
    pub point: Point<F>,
    pub eval: F,
}

impl<E: ExtensionField> Default for PointAndEval<E> {
    fn default() -> Self {
        Self {
            point: vec![],
            eval: E::ZERO,
        }
    }
}

impl<F: Clone> PointAndEval<F> {
    /// Construct a new pair of point and eval.
    /// Caller gives up ownership
    pub fn new(point: Point<F>, eval: F) -> Self {
        Self { point, eval }
    }

    /// Construct a new pair of point and eval.
    /// Performs deep copy.
    pub fn new_from_ref(point: &Point<F>, eval: &F) -> Self {
        Self {
            point: (*point).clone(),
            eval: eval.clone(),
        }
    }
}
