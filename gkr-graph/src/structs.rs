use ff_ext::ExtensionField;
use gkr::structs::{Circuit, CircuitWitness, PointAndEval};
use simple_frontend::structs::WitnessId;
use std::{marker::PhantomData, sync::Arc};

pub(crate) type GKRProverState<F> = gkr::structs::IOPProverState<F>;
pub(crate) type GKRVerifierState<F> = gkr::structs::IOPVerifierState<F>;
pub(crate) type GKRProof<F> = gkr::structs::IOPProof<F>;

/// Corresponds to the `output_evals` and `wires_out_evals` in gkr
/// `prove_parallel`.
pub struct IOPProverState<E: ExtensionField> {
    marker: PhantomData<E>,
}

pub struct IOPProof<E: ExtensionField> {
    pub(crate) gkr_proofs: Vec<GKRProof<E>>,
}

pub struct IOPVerifierState<E: ExtensionField> {
    marker: PhantomData<E>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
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

#[derive(Clone, Debug)]
pub struct CircuitNode<E: ExtensionField> {
    pub(crate) id: usize,
    pub(crate) label: &'static str,
    pub(crate) circuit: Arc<Circuit<E>>,
    // Where does each wire in come from.
    pub(crate) preds: Vec<PredType>,
}

#[derive(Clone, Debug, Default)]
pub struct CircuitGraph<E: ExtensionField> {
    pub(crate) nodes: Vec<CircuitNode<E>>,
    pub(crate) targets: Vec<NodeOutputType>,
    pub(crate) sources: Vec<NodeInputType>,
}

#[derive(Default)]
pub struct CircuitGraphWitness<'a, E: ExtensionField> {
    pub node_witnesses: Vec<Arc<CircuitWitness<'a, E>>>,
}

pub struct CircuitGraphBuilder<'a, E: ExtensionField> {
    pub(crate) graph: CircuitGraph<E>,
    pub(crate) witness: CircuitGraphWitness<'a, E>,
}

#[derive(Clone, Debug, Default)]
pub struct CircuitGraphAuxInfo {
    pub instance_num_vars: Vec<usize>,
}

/// Evaluations corresponds to the circuit targets.
#[derive(Clone, Debug)]
pub struct TargetEvaluations<F>(pub Vec<PointAndEval<F>>);
