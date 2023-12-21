use goldilocks::SmallField;

pub(crate) struct OpcodeStats<F: SmallField> {
    /// The number of times this opcode is executed.
    pub(crate) count: usize,
    pub(crate) witness: Vec<Vec<F>>,
}

pub(crate) struct GlobalStats {
    pub(crate) bytecode_size: usize,
    pub(crate) stack_size: usize,
    pub(crate) memory_size: usize,
    pub(crate) global_state_size: usize,
    pub(crate) bit_op_size: usize,
    pub(crate) range_size: usize,
    pub(crate) hash_size: usize,
}
