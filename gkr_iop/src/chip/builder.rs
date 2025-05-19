use std::array;

use ff_ext::ExtensionField;
use itertools::Itertools;
use multilinear_extensions::{ChallengeId, Expression, WitIn, WitnessId};

use crate::{
    evaluation::EvalExpression,
    gkr::layer::{Layer, LayerType},
};

use super::Chip;

impl<E: ExtensionField> Chip<E> {
    /// Allocate indices for committing base field polynomials.
    pub fn allocate_committed<const N: usize>(&mut self) -> [usize; N] {
        let committed = array::from_fn(|i| i + self.n_committed);
        self.n_committed += N;
        committed
    }

    /// Allocate `Witness` and `EvalExpression` for the input polynomials in a
    /// layer. Where `Witness` denotes the index and `EvalExpression`
    /// denotes the position to place the evaluation of the polynomial after
    /// processing the layer prover for each polynomial. This should be
    /// called at most once for each layer!
    #[allow(clippy::type_complexity)]
    pub fn allocate_wits_in_layer<const N: usize>(&mut self) -> [(WitIn, EvalExpression<E>); N] {
        let bases = array::from_fn(|i| {
            (
                WitIn {
                    id: (i + self.n_evaluations) as WitnessId,
                },
                EvalExpression::Single(i + self.n_evaluations),
            )
        });
        self.n_evaluations += N;
        bases
    }

    /// Generate the evaluation expression for each output.
    pub fn allocate_output_evals<const N: usize>(&mut self) -> Vec<EvalExpression<E>>
// -> [EvalExpression; N]
    {
        // array::from_fn(|i| EvalExpression::Single(i + self.n_evaluations - N))
        // TODO: hotfix to avoid stack overflow, fix later
        let output_evals = (0..N)
            .map(|i| EvalExpression::Single(i + self.n_evaluations))
            .collect_vec();
        self.n_evaluations += N;
        output_evals
    }

    /// Allocate challenges.
    pub fn allocate_challenges<const N: usize>(&mut self) -> [Expression<E>; N] {
        let challanges = array::from_fn(|i| {
            Expression::Challenge((i + self.n_challenges) as ChallengeId, 1, E::ONE, E::ZERO)
        });
        self.n_challenges += N;
        challanges
    }

    /// Allocate a PCS opening action to a base polynomial with index
    /// `wit_index`. The `EvalExpression` represents the expression to
    /// compute the evaluation.
    pub fn allocate_opening(&mut self, wit_index: usize, eval: EvalExpression<E>) {
        self.openings.push((wit_index, eval));
    }

    /// Add a layer to the circuit.
    pub fn add_layer(&mut self, layer: Layer<E>) {
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
