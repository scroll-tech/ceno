use std::{collections::HashMap, sync::Arc};

use goldilocks::SmallField;
use transcript::Challenge;

pub(crate) type SumcheckProof<F: SmallField> = sumcheck::structs::IOPProof<F>;
pub(crate) type Point<F: SmallField> = Vec<Challenge<F>>;

/// Represent the prover state for each layer in the IOP protocol.
pub struct IOPProverState<F: SmallField> {
    pub(crate) layer_id: usize,
    /// Evaluation point used in the proved layers for pasting values from
    /// previous layers.
    pub(crate) layer_eval_points: Vec<HashMap<usize, Point<F>>>,
    /// Evaluations of the connection subset between the proved layers with
    /// previous layers.
    pub(crate) layer_eval_values: Vec<HashMap<usize, F>>,
    pub(crate) circuit_witness: CircuitWitness<F>,
}

/// Represent the verifier state for each layer in the IOP protocol.
pub struct IOPVerifierState<F: SmallField> {
    pub(crate) layer_id: usize,
    /// Evaluation point used in the proved layers for pasting values from
    /// previous layers.
    pub(crate) layer_eval_points: Vec<Point<F>>,
}

pub struct IOPProverPhase1Message<F: SmallField> {
    pub sumcheck_messages: Vec<SumcheckProof<F>>,
    pub evaluation: F,
}

pub struct IOPProverPhase2Message<F: SmallField> {
    pub sumcheck_messages: Vec<SumcheckProof<F>>,
    pub evaluations: Vec<F>,
}

pub struct IOPProverPhase3Message<F: SmallField> {
    pub sumcheck_messages: Vec<SumcheckProof<F>>,
    pub evaluations: Vec<F>,
}

pub struct IOPProof<F: SmallField> {
    pub sumcheck_proofs: Vec<(
        IOPProverPhase1Message<F>,
        IOPProverPhase2Message<F>,
        IOPProverPhase3Message<F>,
    )>,
}

pub struct GKRInputClaims<F: SmallField> {
    pub points: Vec<Point<F>>,
    pub evaluations: Vec<F>,
}

/// Represent a connection between the current layer with layer_id. When a
/// subset of Layer i is copied to Layer j, subset_conn[k] denotes the original
/// index that the k-th wire corresponding to the one in either Layer i or j.
pub struct LayerConnection {
    pub(crate) layer_id: usize,
    pub(crate) subset_conn: Vec<usize>,
}

pub struct Layer<F: SmallField> {
    pub(crate) log_size: usize,
    pub(crate) size: usize,

    // Gates
    pub(crate) adds: Option<Vec<Gate1In<F>>>,
    pub(crate) mul2s: Option<Vec<Gate2In<F>>>,
    pub(crate) mul3s: Option<Vec<Gate3In<F>>>,
    pub(crate) assert_consts: Vec<Option<F>>,

    /// The corresponding wires copied from the output of this layer to deeper
    /// layers.
    pub(crate) copy_to: Vec<LayerConnection>,
    /// The corresponding wires copied from shallower layers to the input of
    /// this layer.
    pub(crate) paste_from: Vec<LayerConnection>,
}

pub struct Circuit<F: SmallField> {
    pub layers: Vec<Layer<F>>,
}

pub struct LayerWitness<F: SmallField>(Vec<F>);

pub struct CircuitWitness<F: SmallField> {
    pub(crate) layers: Vec<LayerWitness<F>>,
    pub(crate) public_input: LayerWitness<F>,
    pub(crate) witnesses: Vec<LayerWitness<F>>,
    pub(crate) challenges: Vec<F>,
}

pub struct Gate1In<F: SmallField> {
    pub(crate) idx_in: usize,
    pub(crate) idx_out: usize,
    pub(crate) scaler: F,
}

pub struct Gate2In<F: SmallField> {
    pub(crate) idx_in1: usize,
    pub(crate) idx_in2: usize,
    pub(crate) idx_out: usize,
    pub(crate) scaler: F,
}

pub struct Gate3In<F: SmallField> {
    pub(crate) idx_in1: usize,
    pub(crate) idx_in2: usize,
    pub(crate) idx_in3: usize,
    pub(crate) idx_out: usize,
    pub(crate) scaler: F,
}
