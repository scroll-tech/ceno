use crate::{evaluation::EvalExpression, gkr::layer::Layer};

pub mod builder;
pub mod protocol;

#[derive(Clone, Debug, Default)]
pub struct Chip {
    pub n_committed_bases: usize,
    pub n_committed_exts: usize,

    pub n_challenges: usize,
    pub n_evaluations: usize,
    pub layers: Vec<Layer>,

    pub base_openings: Vec<(usize, EvalExpression)>,
    pub ext_openings: Vec<(usize, EvalExpression)>,
}
