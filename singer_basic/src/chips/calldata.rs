use goldilocks::SmallField;

pub struct CalldataChip<F: SmallField> {
    _marker: std::marker::PhantomData<F>,
}
