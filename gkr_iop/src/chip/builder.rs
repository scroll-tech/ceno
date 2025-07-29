use ff_ext::ExtensionField;

use crate::gkr::layer::{Layer, LayerType};

use super::Chip;

impl<E: ExtensionField> Chip<E> {
    /// Add a layer to the circuit. Note that we assume the fixed inputs only occur in the first layer.
    pub fn add_layer(&mut self, layer: Layer<E>) {
        assert_eq!(
            layer
                .out_sel_and_eval_exprs
                .iter()
                .map(|(_, outs)| outs.len())
                .sum::<usize>(),
            layer.exprs.len()
        );
        if let LayerType::Linear = layer.ty {
            assert!(layer.exprs.iter().all(|expr| expr.degree() == 1));
        }
        self.layers.push(layer);
    }
}
