use std::sync::Arc;

use gkr::structs::{Circuit, CircuitWitness};
use goldilocks::SmallField;

type GKRProverState<F: SmallField> = gkr::structs::IOPProverState<F>;
type GKRVerifierState<F: SmallField> = gkr::structs::IOPVerifierState<F>;
type GKRProof<F: SmallField> = gkr::structs::IOPProof<F>;

pub type NodeIndex = usize;
pub type WireInIndex = usize;
pub type WireOutIndex = usize;
pub type NodeWireIn = (NodeIndex, WireInIndex);
pub type NodeWireOut = (NodeIndex, Option<WireOutIndex>);

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
    id: NodeIndex,
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
