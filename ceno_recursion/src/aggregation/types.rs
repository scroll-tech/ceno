// TODO: enable this
// #[derive(Debug, Clone, AlignedBorrow)]
// pub struct ContinuationPvs<T> {
//     pub sum: SepticPoint<T>,
// }

// impl<C: Config> ContinuationPvs<Felt<C::F>> {
//     pub fn uninit(builder: &mut Builder<C>) -> Self {
//         todo!()
//     }
// }

// #[derive(Debug, Clone, AlignedBorrow)]
// #[repr(C)]
// pub struct VmVerifierPvs<T> {
//     /// The merged execution state of all the segments this circuit aggregates.
//     pub connector: VmConnectorPvs<T>,
//     /// The state before/after all the segments this circuit aggregates.
//     // (TODO) pub shard_ram_connector: ContinuationPvs<T>,
//     /// The merkle root of all public values. This is only meaningful when the last segment is
//     /// aggregated by this circuit.
//     pub public_values_commit: [T; DIGEST_SIZE],
// }

// impl<C: Config> VmVerifierPvs<Felt<C::F>> {
//     pub fn uninit(builder: &mut Builder<C>) -> Self {
//         VmVerifierPvs {
//             connector: VmConnectorPvs {
//                 initial_pc: builder.uninit(),
//                 final_pc: builder.uninit(),
//                 exit_code: builder.uninit(),
//                 is_terminate: builder.uninit(),
//             },
//             // shard_ram_connector: builder.uninit(),
//             public_values_commit: array::from_fn(|_| builder.uninit()),
//         }
//     }
// }
