use ff_ext::ExtensionField;
use multilinear_extensions::virtual_poly_v2::{ArcMultilinearExtension, VirtualPolynomialV2};
use singer_utils::constants::VALUE_BIT_WIDTH;
use sumcheck::structs::IOPProverMessage;

use crate::uint::UInt;

pub struct TowerProver;

#[derive(Clone)]
pub struct TowerProofs<E: ExtensionField> {
    pub proofs: Vec<Vec<IOPProverMessage<E>>>,
    // specs -> layers -> evals
    pub prod_specs_eval: Vec<Vec<Vec<E>>>,
    // specs -> layers -> evals
    pub logup_specs_eval: Vec<Vec<Vec<E>>>,
}

pub struct TowerProverSpec<'a, E: ExtensionField> {
    pub witness: Vec<Vec<ArcMultilinearExtension<'a, E>>>,
}

pub type UInt64<E> = UInt<64, VALUE_BIT_WIDTH, E>;
pub type PCUInt<E> = UInt64<E>;
pub type TSUInt<E> = UInt<48, 48, E>;

pub enum ROMType {
    U5, // 2^5=32
}

pub struct VirtualPolynomials<'a, E: ExtensionField> {
    pub num_threads: usize,
    pub polys: Vec<VirtualPolynomialV2<'a, E>>,
}
