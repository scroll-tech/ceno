use std::{collections::HashMap, sync::Arc};

use frontend::structs::{CellId, ConstantType, InType, LayerId};
use goldilocks::SmallField;
use multilinear_extensions::mle::DenseMultilinearExtension;
use serde::Serialize;

pub(crate) type SumcheckProof<F> = sumcheck::structs::IOPProof<F>;
pub(crate) type Point<F> = Vec<F>;

/// Represent the prover state for each layer in the IOP protocol. To support
/// gates between non-adjeacent layers, we leverage the techniques in
/// [Virgo++](https://eprint.iacr.org/2020/1247).
pub struct IOPProverState<F: SmallField> {
    pub(crate) layer_id: LayerId,
    /// Evaluations from the next layer.
    pub(crate) next_evals: Vec<(Point<F>, F)>,
    /// Evaluations of subsets from layers closer to the output. Hashmap is used
    /// to map from the current layer id to the later layer id, point and value.
    pub(crate) subset_evals: HashMap<LayerId, Vec<(LayerId, Point<F>, F)>>,
    pub(crate) circuit_witness: CircuitWitness<F>,
    pub(crate) layer_out_poly: Arc<DenseMultilinearExtension<F>>,
}

/// Represent the verifier state for each layer in the IOP protocol.
pub struct IOPVerifierState<F: SmallField> {
    pub(crate) layer_id: LayerId,
    /// Evaluations from the next layer.
    pub(crate) next_evals: Vec<(Point<F>, F)>,
    /// Evaluations of subsets from layers closer to the output. Hashmap is used
    /// to map from the current layer id to the deeper layer id, point and
    /// value.
    pub(crate) subset_evals: HashMap<LayerId, Vec<(LayerId, Point<F>, F)>>,
}

/// Phase 1 is a sumcheck protocol merging the subset evaluations from the
/// layers closer to the circuit output to an evaluation to the output of the
/// current layer.
pub struct IOPProverPhase1Message<F: SmallField> {
    pub sumcheck_proof_1: SumcheckProof<F>,
    pub eval_value_1: Vec<F>,
    pub sumcheck_proof_2: SumcheckProof<F>,
    /// Evaluation of the output of the current layer.
    pub eval_value_2: F,
}

/// Phase 2 is several sumcheck protocols (depending on the degree of gates),
/// reducing the correctness of the output of the current layer to the input of
/// the current layer.
pub struct IOPProverPhase2Message<F: SmallField> {
    /// Sumcheck proofs for each sumcheck protocol.
    pub sumcheck_proofs: Vec<SumcheckProof<F>>,
    pub sumcheck_eval_values: Vec<Vec<F>>,
}

pub struct IOPProof<F: SmallField> {
    pub sumcheck_proofs: Vec<(Option<IOPProverPhase1Message<F>>, IOPProverPhase2Message<F>)>,
}

/// Represent the point at the final step and the evaluations of the subsets of
/// the input layer.
pub struct GKRInputClaims<F: SmallField> {
    pub point: Point<F>,
    pub values: Vec<F>,
}

#[derive(Clone, Serialize)]
pub struct Layer<F: SmallField> {
    pub(crate) num_vars: usize,

    // Gates. Should be all None if it's the input layer.
    pub(crate) add_consts: Vec<GateCIn<ConstantType<F>>>,
    pub(crate) adds: Vec<Gate1In<ConstantType<F>>>,
    pub(crate) mul2s: Vec<Gate2In<ConstantType<F>>>,
    pub(crate) mul3s: Vec<Gate3In<ConstantType<F>>>,
    pub(crate) assert_consts: Vec<GateCIn<ConstantType<F>>>,

    /// The corresponding wires copied from this layer to later layers. It is
    /// (later layer id -> current wire id to be copied). It stores the non-zero
    /// entry of copy_to[layer_id] for each row.
    pub(crate) copy_to: HashMap<LayerId, Vec<CellId>>,
    /// The corresponding wires from previous layers pasted to this layer. It is
    /// (shallower layer id -> pasted to the current id). It stores the non-zero
    /// entry of paste_from[layer_id] for each column. Undefined for the input.
    pub(crate) paste_from: HashMap<LayerId, Vec<CellId>>,
    /// Maximum size of the subsets pasted from the previous layers, rounded up
    /// to the next power of two. This is the logarithm of the rounded size.
    /// Undefined for the input layer.
    pub(crate) max_previous_num_vars: usize,
}

#[derive(Clone, Serialize)]
pub struct Circuit<F: SmallField> {
    pub layers: Vec<Layer<F>>,
    /// Copied from the circuit output to segments for convenience of later use.
    pub copy_to_wires_out: Vec<Vec<CellId>>,

    pub n_wires_in: usize,
    /// The left endpoint in the input layer copied from each wire_in.
    pub paste_from_in: Vec<(InType, CellId, CellId)>,
    pub max_wires_in_num_vars: usize,
}

#[derive(Clone, Debug, Serialize)]
pub struct GateCIn<C> {
    pub(crate) idx_out: CellId,
    pub(crate) constant: C,
}

#[derive(Clone, Debug, Serialize)]
pub struct Gate1In<C> {
    pub(crate) idx_in: CellId,
    pub(crate) idx_out: CellId,
    pub(crate) scaler: C,
}

#[derive(Clone, Debug, Serialize)]
pub struct Gate2In<C> {
    pub(crate) idx_in1: CellId,
    pub(crate) idx_in2: CellId,
    pub(crate) idx_out: CellId,
    pub(crate) scaler: C,
}

#[derive(Clone, Debug, Serialize)]
pub struct Gate3In<C> {
    pub(crate) idx_in1: CellId,
    pub(crate) idx_in2: CellId,
    pub(crate) idx_in3: CellId,
    pub(crate) idx_out: CellId,
    pub(crate) scaler: C,
}

#[derive(Clone, Serialize)]
pub struct CircuitWitness<F: SmallField> {
    /// Three vectors denote 1. layer_id, 2. instance_id, 3. wire_id.
    pub(crate) layers: Vec<Vec<Vec<F>>>,
    pub(crate) wires_in: Vec<Vec<Vec<F>>>,
    pub(crate) wires_out: Vec<Vec<Vec<F>>>,
    /// Challenges
    pub(crate) challenges: Vec<F>,
    /// The number of instances for the same sub-circuit.
    pub(crate) n_instances: usize,
}
