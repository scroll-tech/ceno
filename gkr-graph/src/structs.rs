use gkr::structs::{Circuit, CircuitWitness, Point, PointAndEval};
use goldilocks::SmallField;
use simple_frontend::structs::WitnessId;
use std::sync::Arc;

pub(crate) type GKRProverState<F> = gkr::structs::IOPProverState<F>;
pub(crate) type GKRVerifierState<F> = gkr::structs::IOPVerifierState<F>;
pub(crate) type GKRProof<F> = gkr::structs::IOPProof<F>;

/// Corresponds to the `output_evals` and `wires_out_evals` in gkr
/// `prove_parallel`.
pub struct IOPProverState<F: SmallField> {
    output_evals: Vec<Option<(Point<F>, F)>>,
    wire_out_evals: Vec<Vec<Option<(Point<F>, F)>>>,

    graph: CircuitGraph<F>,
    witness: CircuitGraphWitness<F>,
}

pub struct IOPProof<F: SmallField> {
    pub(crate) gkr_proofs: Vec<GKRProof<F>>,
}

pub struct IOPVerifierState<F: SmallField> {
    marker: std::marker::PhantomData<F>,
}

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum NodeInputType {
    WireIn(usize, WitnessId),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum NodeOutputType {
    OutputLayer(usize),
    WireOut(usize, WitnessId),
}

/// The predecessor of a node can be a source or a wire. If it is a wire, it can
/// be one wire_out instance connected to one wire_in instance, or one wire_out
/// connected to multiple wire_in instances.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum PredType {
    Source,
    PredWire(NodeOutputType),
    PredWireDup(NodeOutputType),
}

pub struct CircuitNode<F: SmallField> {
    pub(crate) id: usize,
    pub(crate) label: &'static str,
    pub(crate) circuit: Arc<Circuit<F>>,
    // Where does each wire in come from.
    pub(crate) preds: Vec<PredType>,
}

#[derive(Default)]
pub struct CircuitGraph<F: SmallField> {
    pub(crate) nodes: Vec<CircuitNode<F>>,
    pub(crate) targets: Vec<NodeOutputType>,
    pub(crate) sources: Vec<NodeInputType>,
}

#[derive(Default)]
pub struct CircuitGraphWitness<F: SmallField> {
    pub node_witnesses: Vec<CircuitWitness<F>>,
}

pub struct CircuitGraphBuilder<F: SmallField> {
    pub(crate) graph: CircuitGraph<F>,
    pub(crate) witness: CircuitGraphWitness<F::BaseField>,
}

pub struct CircuitGraphAuxInfo {
    pub instance_num_vars: Vec<usize>,
}

/// Evaluations corresponds to the circuit targets.
#[derive(Clone)]
pub struct TargetEvaluations<F>(pub Vec<PointAndEval<F>>);
