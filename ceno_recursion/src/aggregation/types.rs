
use openvm_continuations::F;
use ceno_zkvm::scheme::{constants::SEPTIC_EXTENSION_DEGREE, septic_curve::SepticPoint};
use openvm_circuit::system::connector::VmConnectorPvs;
use crate::zkvm_verifier::binding::{SepticPointVariable, SepticExtensionVariable};
use openvm_native_compiler::{
    prelude::*,
    ir::{Array, Builder, Config, DIGEST_SIZE, Felt, Variable},
};
use std::array;

#[derive(Clone)]
pub struct ContinuationPvs<C: Config> {
    pub xy: [Felt<C::F>; SEPTIC_EXTENSION_DEGREE * 2],
    pub is_infinity: Usize<C::N>,
}

impl<C: Config> ContinuationPvs<C> {
    pub fn uninit(builder: &mut Builder<C>) -> Self {
        Self {
            xy: array::from_fn(|_| builder.uninit()),
            is_infinity: Usize::uninit(builder),
        }
    }
}

#[derive(Clone)]
#[repr(C)]
pub struct VmVerifierPvs<C: Config> {
    /// The merged execution state of all the segments this circuit aggregates.
    pub connector: VmConnectorPvs<Felt<C::F>>,
    /// The state before/after all the segments this circuit aggregates.
    pub shard_ram_connector: ContinuationPvs<C>,
    /// The merkle root of all public values. This is only meaningful when the last segment is
    /// aggregated by this circuit.
    pub public_values_commit: [Felt<C::F>; DIGEST_SIZE],
}

impl<C: Config> VmVerifierPvs<C> {
    pub fn uninit(builder: &mut Builder<C>) -> Self {
        VmVerifierPvs {
            connector: VmConnectorPvs {
                initial_pc: builder.uninit(),
                final_pc: builder.uninit(),
                exit_code: builder.uninit(),
                is_terminate: builder.uninit(),
            },
            shard_ram_connector: ContinuationPvs::uninit(builder),
            public_values_commit: array::from_fn(|_| builder.uninit()),
        }
    }
}
