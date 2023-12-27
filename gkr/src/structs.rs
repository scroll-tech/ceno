use std::{collections::HashMap, sync::Arc};

use frontend::structs::ConstantType;
use goldilocks::SmallField;
use multilinear_extensions::mle::DenseMultilinearExtension;
use transcript::Challenge;

pub(crate) type SumcheckProof<F> = sumcheck::structs::IOPProof<F>;
pub(crate) type Point<F> = Vec<Challenge<F>>;

/// Represent the prover state for each layer in the IOP protocol. To support
/// gates between non-adjeacent layers, we leverage the techniques in
/// [Virgo++](https://eprint.iacr.org/2020/1247).
pub struct IOPProverState<F: SmallField> {
    pub(crate) layer_id: usize,
    /// Evaluations and points used in the proved layers for pasting values from
    /// previous layers. Hashmap is used to map from the layer id to the point
    /// and value.
    pub(crate) layer_evals: HashMap<usize, (Point<F>, F)>,
    pub(crate) circuit_witness: CircuitWitness<F>,
}

/// Represent the verifier state for each layer in the IOP protocol.
pub struct IOPVerifierState<F: SmallField> {
    pub(crate) layer_id: usize,
    /// Evaluation point used in the proved layers for pasting values from
    /// previous layers. Hashmap is used to map from the layer id to the point.
    pub(crate) layer_eval_points: HashMap<usize, Point<F>>,
}

/// Phase 1 is a sumcheck protocol merging the subset evaluations from the
/// layers closer to the circuit output to an evaluation to the output of the
/// current layer.
pub struct IOPProverPhase1Message<F: SmallField> {
    pub sumcheck_messages: SumcheckProof<F>,
    /// Evaluation of the output of the current layer.
    pub evaluation: F,
}

/// Phase 2 is several sumcheck protocols (depending on the degree of gates),
/// reducing the correctness of the output of the current layer to the input of
/// the current layer.
pub struct IOPProverPhase2Message<F: SmallField> {
    /// Sumcheck messages for each sumcheck protocol.
    pub sumcheck_messages: Vec<SumcheckProof<F>>,
    /// Evaluations sent by the prover at the end of each sumcheck protocol.
    pub evaluations: Vec<Vec<F>>,
}

pub struct IOPProof<F: SmallField> {
    pub sumcheck_proofs: Vec<(IOPProverPhase1Message<F>, IOPProverPhase2Message<F>)>,
}

/// Represent the point at the final step and the evaluations of the subsets of
/// the input layer.
pub struct GKRInputClaims<F: SmallField> {
    pub point: Point<F>,
    pub evaluations: Vec<F>,
}

#[derive(Clone, Debug)]
pub struct Layer<F: SmallField> {
    pub(crate) num_vars: usize,

    // Gates. Should be all None if it's the input layer.
    pub(crate) add_consts: Vec<GateCIn<F>>,
    pub(crate) adds: Vec<Gate1In<F>>,
    pub(crate) mul2s: Vec<Gate2In<F>>,
    pub(crate) mul3s: Vec<Gate3In<F>>,
    pub(crate) assert_consts: Vec<GateCIn<F>>,

    /// The corresponding wires copied from this layer to later layers. It is
    /// (later layer id -> current wire id to be copied). It stores the non-zero
    /// entry of copy_from[layer_id] for each row.
    pub(crate) copy_from: HashMap<usize, Vec<usize>>,
    /// The corresponding wires from previous layers pasted to this layer. It is
    /// (shallower layer id -> pasted to the current id). It stores the non-zero
    /// entry of paste_to[layer_id] for each column.
    pub(crate) paste_to: HashMap<usize, Vec<usize>>,
}

#[derive(Clone, Debug)]
pub struct Circuit<F: SmallField> {
    pub layers: Vec<Layer<F>>,
    pub output_copy_from: Vec<Vec<usize>>,
    pub n_wires_in: usize,
    pub n_other_witnesses: usize,
}

pub struct LayerWitness<F: SmallField> {
    pub(crate) poly: Arc<DenseMultilinearExtension<F>>,
}

pub struct CircuitWitness<F: SmallField> {
    pub(crate) layers: Vec<LayerWitness<F>>,
    pub(crate) wires_in: Vec<LayerWitness<F>>,
    pub(crate) wires_out: Vec<LayerWitness<F>>,
    pub(crate) other_witnesses: Vec<LayerWitness<F>>,
    pub(crate) n_instances: usize,
}

#[derive(Clone, Debug)]
pub struct GateCIn<F: SmallField> {
    pub(crate) idx_out: usize,
    pub(crate) constant: ConstantType<F>,
}

#[derive(Clone, Debug)]
pub struct Gate1In<F: SmallField> {
    pub(crate) idx_in: usize,
    pub(crate) idx_out: usize,
    pub(crate) scaler: ConstantType<F>,
}

#[derive(Clone, Debug)]
pub struct Gate2In<F: SmallField> {
    pub(crate) idx_in1: usize,
    pub(crate) idx_in2: usize,
    pub(crate) idx_out: usize,
    pub(crate) scaler: ConstantType<F>,
}

#[derive(Clone, Debug)]
pub struct Gate3In<F: SmallField> {
    pub(crate) idx_in1: usize,
    pub(crate) idx_in2: usize,
    pub(crate) idx_in3: usize,
    pub(crate) idx_out: usize,
    pub(crate) scaler: ConstantType<F>,
}

#[derive(Clone, Debug)]
pub struct CircuitWitnessGenerator<F: SmallField> {
    pub(crate) layers: Vec<Vec<F>>,
    pub(crate) wires_in: Vec<Vec<F>>,
    pub(crate) wires_out: Vec<Vec<F>>,
    pub(crate) other_witnesses: Vec<Vec<F>>,
    /// Challenges
    pub(crate) challenges: Vec<F>,
    /// The number of instances for the same sub-circuit.
    pub(crate) n_instances: usize,
}
