pub(crate) const MIN_PAR_SIZE: usize = 64;

pub const NUM_FANIN: usize = 2;
pub const NUM_FANIN_LOGUP: usize = 2;

pub const MAX_NUM_VARIABLES: usize = 29;
pub const MAX_NUM_INSTANCE_BITS: usize = 28;
/// Exclusive upper bound for each proof-controlled `num_instances` entry.
pub const MAX_NUM_INSTANCES: usize = 1usize << MAX_NUM_INSTANCE_BITS;

pub const DYNAMIC_RANGE_MAX_BITS: usize = 18;

pub const SEPTIC_EXTENSION_DEGREE: usize = 7;
pub const SEPTIC_JACOBIAN_NUM_MLES: usize = 3 * SEPTIC_EXTENSION_DEGREE;
