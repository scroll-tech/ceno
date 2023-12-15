use goldilocks::SmallField;

use self::connections::{Gate1In, Gate2In, Gate3In};

mod connections;

pub struct LayerConnection<F: SmallField>(usize, Vec<Gate1In<F>>);

pub struct Layer<F: SmallField> {
    log_size: usize,
    size: usize,

    // Gates
    adds: Vec<Gate1In<F>>,
    mul2s: Vec<Gate2In<F>>,
    mul3s: Vec<Gate3In<F>>,
    assert_consts: Vec<F>,

    // Pairs of layer idx and connect relation. Extract a subset which is connected to the later layers.
    copy_to: Vec<LayerConnection<F>>,
    // Pairs of layer idx and connect relation. Connect to a subset of the previous layers.
    paste_from: Vec<LayerConnection<F>>,
}

pub struct Circuit<F: SmallField> {
    layers: Vec<Layer<F>>,
}