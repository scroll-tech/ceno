use ff_ext::ExtensionField;
use itertools::izip;

use crate::{
    structs_v2::CircuitBuilderV2,
    util_v2::{ExpressionV2, ZKVMV2Error},
};

use super::UIntV2;

impl<const M: usize, const C: usize> UIntV2<M, C> {
    pub fn add_const<E: ExtensionField>(
        &self,
        _circuit_builder: &CircuitBuilderV2<E>,
        _constant: ExpressionV2<E>,
    ) -> Result<Self, ZKVMV2Error> {
        // TODO
        Ok(self.clone())
    }

    /// Little-endian addition.
    pub fn add<E: ExtensionField>(
        &self,
        circuit_builder: &mut CircuitBuilderV2<E>,
        addend_1: &UIntV2<M, C>,
    ) -> Result<UIntV2<M, C>, ZKVMV2Error> {
        // TODO
        Ok(self.clone())
    }

    /// Little-endian addition.
    pub fn eq<E: ExtensionField>(
        &self,
        circuit_builder: &mut CircuitBuilderV2<E>,
        rhs: &UIntV2<M, C>,
    ) -> Result<(), ZKVMV2Error> {
        izip!(self.expr(), rhs.expr())
            .try_for_each(|(lhs, rhs)| circuit_builder.require_equal(lhs, rhs))
    }

    pub fn lt<E: ExtensionField>(
        &self,
        circuit_builder: &mut CircuitBuilderV2<E>,
        rhs: &UIntV2<M, C>,
    ) -> Result<ExpressionV2<E>, ZKVMV2Error> {
        Ok(self.expr().remove(0) + 1.into())
    }
}
