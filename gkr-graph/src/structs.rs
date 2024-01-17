use std::sync::Arc;

use frontend::structs::WireId;
use gkr::structs::{Circuit, CircuitWitness};
use goldilocks::SmallField;

type GKRProverState<F: SmallField> = gkr::structs::IOPProverState<F>;
type GKRVerifierState<F: SmallField> = gkr::structs::IOPVerifierState<F>;
type GKRProof<F: SmallField> = gkr::structs::IOPProof<F>;

pub struct NodeWireIn {
    node_id: usize,
    prep_wire_id: WireId,
    /// The number of variables of the preceding nodes.
    num_vars: usize,
}

pub struct NodeWireOut {
    node_id: usize,
    succ_wire_id: WireId,
    /// The number of variables of the succeeding nodes.
    num_vars: usize,
}

pub struct IOPProverState<F: SmallField> {
    marker: std::marker::PhantomData<F>,
}

pub struct IOPProof<F: SmallField> {
    gkr_proofs: Vec<GKRProof<F>>,
}

pub struct IOPVerifierState<F: SmallField> {
    marker: std::marker::PhantomData<F>,
}

pub struct CircuitNode<F: SmallField> {
    id: usize,
    circuit: Arc<Circuit<F>>,
    // Each wire_in comes from a wire_out of a node
    predecessors: Vec<NodeWireOut>,
    // Each wire_out goes to a wire_in of multiple nodes
    successors: Vec<Vec<NodeWireIn>>,
}

pub struct CircuitGraph<F: SmallField> {
    nodes: Vec<CircuitNode<F>>,
    target_wires: Vec<NodeWireOut>,
    source_wires: Vec<NodeWireIn>,
}

pub struct CircuitGraphWitness<F: SmallField> {
    node_witnesses: Vec<CircuitWitness<F>>,
    circuit_aux_info: CircuitGraphAuxInfo,
}

pub struct CircuitGraphAuxInfo {}

pub(crate) type Point<F> = Vec<F>;

pub struct TargetEvaluations<F: SmallField> {
    marker: std::marker::PhantomData<F>,
}
