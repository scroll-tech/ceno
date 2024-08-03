use ff_ext::ExtensionField;
use multilinear_extensions::virtual_poly_v2::ArcMultilinearExtension;
use singer_utils::constants::VALUE_BIT_WIDTH;
use sumcheck::structs::IOPProverMessage;

use crate::uint::UInt;

pub struct TowerProver;

#[derive(Clone)]
pub struct TowerProofs<E: ExtensionField> {
    pub proofs: Vec<Vec<IOPProverMessage<E>>>,
    // specs -> layers -> evals
    pub specs_eval: Vec<Vec<Vec<E>>>,
}

pub struct TowerProverSpec<'a, E: ExtensionField> {
    pub witness: Vec<Vec<ArcMultilinearExtension<'a, E>>>,
}

pub type UInt64 = UInt<64, VALUE_BIT_WIDTH>;
pub type PCUInt = UInt64;
pub type TSUInt = UInt<48, 48>;
