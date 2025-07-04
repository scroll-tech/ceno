pub type ConstraintSystem<E> = gkr_iop::circuit_builder::ConstraintSystem<E>;
pub type NameSpace = gkr_iop::circuit_builder::NameSpace;
pub type SetTableSpec = gkr_iop::circuit_builder::SetTableSpec;
pub type CircuitBuilder<'a, E> = gkr_iop::circuit_builder::CircuitBuilder<'a, E>;

// pub struct CircuitBuilder<'a, E: ExtensionField> {
//     pub inner: gkr_iop::circuit_builder::CircuitBuilder<'a, E>,
//     pub params: ProgramParams,
// }

// impl<'a, E: ExtensionField> Deref for CircuitBuilder<'a, E> {
//     type Target = gkr_iop::circuit_builder::CircuitBuilder<'a, E>;
//     fn deref(&self) -> &Self::Target {
//         &self.inner
//     }
// }

// impl<'a, E: ExtensionField> DerefMut for CircuitBuilder<'a, E> {
//     fn deref_mut(&mut self) -> &mut Self::Target {
//         &mut self.inner
//     }
// }
