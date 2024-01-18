use std::sync::Arc;

use frontend::structs::WireId;
use gkr::structs::{Circuit, CircuitWitness, Point};
use goldilocks::SmallField;

type GKRProverState<F> = gkr::structs::IOPProverState<F>;
type GKRVerifierState<F> = gkr::structs::IOPVerifierState<F>;
type GKRProof<F> = gkr::structs::IOPProof<F>;

/// Corresponds to the `output_evals` and `wires_out_evals` in gkr
/// `prove_parallel`.
pub struct IOPProverState<F: SmallField> {
    output_evals: Vec<Option<(Point<F>, F)>>,
    wire_out_evals: Vec<Vec<Option<(Point<F>, F)>>>,

    graph: CircuitGraph<F>,
    witness: CircuitGraphWitness<F>,
}

pub struct IOPProof<F: SmallField> {
    gkr_proofs: Vec<GKRProof<F>>,
}

pub struct IOPVerifierState<F: SmallField> {
    marker: std::marker::PhantomData<F>,
}

pub(crate) enum NodeInputType {
    WireIn(usize, WireId),
}

pub(crate) enum NodeOutputType {
    OutputLayer(usize),
    WireOut(usize, WireId),
}

/// The predecessor of a node can be a source or a wire. If it is a wire, it can
/// be one wire_out instance connected to one wire_in instance, or one wire_out
/// connected to multiple wire_in instances.
pub(crate) enum PredType {
    Source,
    PredWireO2O(NodeOutputType),
    PredWireO2M(NodeOutputType),
}

pub struct CircuitNode<F: SmallField> {
    id: usize,
    circuit: Arc<Circuit<F>>,
    // Where does each wire in come from.
    preds: Vec<PredType>,
}

pub struct CircuitGraph<F: SmallField> {
    pub(crate) nodes: Vec<CircuitNode<F>>,
    pub(crate) targets: Vec<NodeInputType>,
    pub(crate) sources: Vec<NodeOutputType>,
}

pub struct CircuitGraphWitness<F: SmallField> {
    pub(crate) node_witnesses: Vec<CircuitWitness<F>>,
}

pub struct CircuitGraphBuilder<F: SmallField> {
    graph: CircuitGraph<F>,
    witness: CircuitGraphWitness<F>,
}

pub struct CircuitGraphAuxInfo {}

/// Evaluations corresponds to the circuit targets.
pub struct TargetEvaluations<F: SmallField>(Vec<(Point<F>, F)>);
