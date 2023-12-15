use goldilocks::SmallField;

use crate::circuit::{Circuit, Layer};

pub struct LayerWitness<F: SmallField>(Vec<F>);

trait LayerEvaluator<F: SmallField> {
    fn evaluate(&self, layer: &Layer<F>, input: &[F]) -> LayerWitness<F>;
}

trait ParallelLayerEvaluator<F: SmallField> {
    fn evaluate(&self, layer: &Layer<F>, layer_witness: &mut LayerWitness<F>, input: &[F]);
}

pub struct CircuitWitness<F: SmallField> {
    pub(super) layers: Vec<LayerWitness<F>>,
}

impl<F: SmallField> CircuitWitness<F> {
    pub fn new() -> Self {
        Self { layers: Vec::new() }
    }
}

trait CircuitEvaluator<F: SmallField> {
    fn evaluate(&self, circuit: &Circuit<F>, input: &[F]) -> CircuitWitness<F>;
}

trait ParallelCircuitEvaluator<F: SmallField> {
    fn evaluate(&self, circuit: &Circuit<F>, circuit_witness: &mut CircuitWitness<F>, input: &[F]);
}
