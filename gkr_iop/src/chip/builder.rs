use std::array;

use subprotocols::expression::{Constant, Witness};

use crate::{
    evaluation::EvalExpression,
    gkr::layer::{Layer, LayerType},
};

use super::Chip;

impl Chip {
    /// Allocate indices for committing base field polynomials.
    pub fn allocate_committed_base<const N: usize>(&mut self) -> [usize; N] {
        self.n_committed_bases += N;
        array::from_fn(|i| i + self.n_committed_bases - N)
    }

    /// Allocate indices for committing extension field polynomials.
    pub fn allocate_committed_ext<const N: usize>(&mut self) -> [usize; N] {
        self.n_committed_exts += N;
        array::from_fn(|i| i + self.n_committed_exts - N)
    }

    /// Allocate `Witness` and `EvalExpression` for the input polynomials in a layer.
    /// Where `Witness` denotes the index and `EvalExpression` denotes the position
    /// to place the evaluation of the polynomial after processing the layer prover
    /// for each polynomial. This should be called at most once for each layer!
    #[allow(clippy::type_complexity)]
    pub fn allocate_wits_in_layer<const M: usize, const N: usize>(
        &mut self,
    ) -> (
        [(Witness, EvalExpression); M],
        [(Witness, EvalExpression); N],
    ) {
        let bases = array::from_fn(|i| {
            (
                Witness::BasePoly(i),
                EvalExpression::Single(i + self.n_evaluations),
            )
        });
        self.n_evaluations += M;
        let exts = array::from_fn(|i| {
            (
                Witness::ExtPoly(i),
                EvalExpression::Single(i + self.n_evaluations),
            )
        });
        self.n_evaluations += N;
        (bases, exts)
    }

    /// Generate the evaluation expression for each output.
    pub fn allocate_output_evals<const N: usize>(&mut self) -> [EvalExpression; N] {
        self.n_evaluations += N;
        array::from_fn(|i| EvalExpression::Single(i + self.n_evaluations - N))
    }

    /// Allocate challenges.
    pub fn allocate_challenges<const N: usize>(&mut self) -> [Constant; N] {
        self.n_challenges += N;
        array::from_fn(|i| Constant::Challenge(i + self.n_challenges - N))
    }

    /// Allocate a PCS opening action to a base polynomial with index `wit_index`.
    /// The `EvalExpression` represents the expression to compute the evaluation.
    pub fn allocate_base_opening(&mut self, wit_index: usize, eval: EvalExpression) {
        self.base_openings.push((wit_index, eval));
    }

    /// Allocate a PCS opening action to an ext polynomial with index `wit_index`.
    /// The `EvalExpression` represents the expression to compute the evaluation.
    pub fn allocate_ext_opening(&mut self, wit_index: usize, eval: EvalExpression) {
        self.ext_openings.push((wit_index, eval));
    }

    /// Add a layer to the circuit.
    pub fn add_layer(&mut self, layer: Layer) {
        assert_eq!(layer.outs.len(), layer.exprs.len());
        match layer.ty {
            LayerType::Linear => {
                assert!(layer.exprs.iter().all(|expr| expr.degree() == 1));
            }
            LayerType::Sumcheck => {
                assert_eq!(layer.exprs.len(), 1);
            }
            _ => {}
        }
        self.layers.push(layer);
    }
}
