use goldilocks::SmallField;

pub(super) struct Gate1In<F: SmallField> {
    idx_in: usize,
    idx_out: usize,
    scales: F,
}

pub(super) struct Gate2In<F: SmallField> {
    idx_in1: usize,
    idx_in2: usize,
    idx_out: usize,
    scales: F,
}

pub(super) struct Gate3In<F: SmallField> {
    idx_in1: usize,
    idx_in2: usize,
    idx_in3: usize,
    idx_out: usize,
    scales: F,
}
