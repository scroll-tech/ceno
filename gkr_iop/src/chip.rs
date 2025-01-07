use crate::{evaluation::EvalExpression, gkr::layer::Layer};

pub mod builder;
pub mod protocol;

#[derive(Clone, Debug, Default)]
pub struct Chip {
    /// The number of base inputs committed in the whole protocol.
    pub n_committed_bases: usize,
    /// The number of ext inputs committed in the whole protocol.
    pub n_committed_exts: usize,

    /// The number of challenges generated through the whole protocols
    /// (except the ones inside sumcheck protocols).
    pub n_challenges: usize,
    /// All input evaluations generated at the end of layer protocols will be stored
    /// in a vector and this is the length.
    pub n_evaluations: usize,
    /// The layers of the GKR circuit, in the order outputs-to-inputs.
    pub layers: Vec<Layer>,

    /// The polynomial index and evaluation expressions of the base inputs.
    pub base_openings: Vec<(usize, EvalExpression)>,
    /// The polynomial index and evaluation expressions of the ext inputs.
    pub ext_openings: Vec<(usize, EvalExpression)>,
}
