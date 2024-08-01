use ff_ext::ExtensionField;
use multilinear_extensions::virtual_poly_v2::ArcMultilinearExtension;
use sumcheck::structs::IOPProverMessage;

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
