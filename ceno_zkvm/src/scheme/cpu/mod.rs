use ff_ext::ExtensionField;
use mpcs::{Basefold, RSCodeDefaultSpec};
use multilinear_extensions::virtual_poly::ArcMultilinearExtension;
use p3::matrix::dense::RowMajorMatrix;

use super::hal::ProverBackend;

struct CpuBackend<E> {}

impl<E: ExtensionField> ProverBackend<E> for CpuBackend<E> {
    type E = E;
    type Matrix = RowMajorMatrix<E::BaseField>;
    type MultilinearPoly = ArcMultilinearExtension<E>;
    type PcsData = Basefold<E, RSCodeDefaultSpec<E>>;
}

struct CpuTowerProver {}

impl TowerProver<CpuBackend<E>> for CpuTowerProver {
    fn build_witness(
        &self,
        polys: &[CpuBackend::MultilinearPoly],
        read_exprs: &[Expression<CpuBackend::E>],
        write_exprs: &[Expression<CpuBackend::E>],
        lookup_exprs: &[Expression<CpuBackend::E>],
    ) -> (TowerProverSpec<CpuBackend>, TowerProverSpec<CpuBackend>) {
    }
}
