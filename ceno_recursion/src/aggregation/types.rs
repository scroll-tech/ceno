use ceno_zkvm::scheme::constants::SEPTIC_EXTENSION_DEGREE;
use openvm_circuit::{circuit_derive::AlignedBorrow, system::connector::VmConnectorPvs};
use openvm_native_compiler::ir::{Builder, Config, DIGEST_SIZE, Felt, Variable};
use p3::field::PrimeField32;
use std::{array, borrow::BorrowMut};

#[derive(Clone, Copy, AlignedBorrow)]
pub struct ContinuationPvs<T> {
    pub x: [T; SEPTIC_EXTENSION_DEGREE],
    pub y: [T; SEPTIC_EXTENSION_DEGREE],
    pub is_infinity: T,
}

impl<F: PrimeField32> ContinuationPvs<Felt<F>> {
    pub fn uninit<C: Config<F = F>>(builder: &mut Builder<C>) -> Self {
        Self {
            x: array::from_fn(|_| builder.uninit()),
            y: array::from_fn(|_| builder.uninit()),
            is_infinity: Felt::uninit(builder),
        }
    }
}

#[derive(Clone, Copy, AlignedBorrow)]
#[repr(C)]
pub struct VmVerifierPvs<T> {
    /// The merged execution state of all the segments this circuit aggregates.
    pub connector: VmConnectorPvs<T>,
    /// The state before/after all the segments this circuit aggregates.
    pub shard_ram_connector: ContinuationPvs<T>,
    /// The merkle root of all public values. This is only meaningful when the last segment is
    /// aggregated by this circuit.
    pub public_values_commit: [T; DIGEST_SIZE],
}

impl<F: PrimeField32> VmVerifierPvs<Felt<F>> {
    pub fn uninit<C: Config<F = F>>(builder: &mut Builder<C>) -> Self {
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

impl<F: Default + Clone> VmVerifierPvs<Felt<F>> {
    pub fn flatten(self) -> Vec<Felt<F>> {
        let mut v = vec![Felt(0, Default::default()); VmVerifierPvs::<u8>::width()];
        *v.as_mut_slice().borrow_mut() = self;
        v
    }
}

/// Aggregated state of all segments
#[derive(Clone, Copy, AlignedBorrow)]
#[repr(C)]
pub struct InternalVmVerifierPvs<T> {
    pub vm_verifier_pvs: VmVerifierPvs<T>,
    pub extra_pvs: InternalVmVerifierExtraPvs<T>,
}

/// Extra PVs for internal VM verifier except VmVerifierPvs.
#[derive(Clone, Copy, AlignedBorrow)]
#[repr(C)]
pub struct InternalVmVerifierExtraPvs<T> {
    /// The commitment of the leaf verifier program.
    pub leaf_verifier_commit: [T; DIGEST_SIZE],
    /// For recursion verification, a program need its own commitment, but its own commitment
    /// cannot be hardcoded inside the program itself. So the commitment has to be read from
    /// external and be committed.
    pub internal_program_commit: [T; DIGEST_SIZE],
}

impl<F: PrimeField32> InternalVmVerifierPvs<Felt<F>> {
    pub fn uninit<C: Config<F = F>>(builder: &mut Builder<C>) -> Self {
        Self {
            vm_verifier_pvs: VmVerifierPvs::<Felt<F>>::uninit(builder),
            extra_pvs: InternalVmVerifierExtraPvs::<Felt<F>>::uninit(builder),
        }
    }
}

impl<F: Default + Clone> InternalVmVerifierPvs<Felt<F>> {
    pub fn flatten(self) -> Vec<Felt<F>> {
        let mut v = vec![Felt(0, Default::default()); InternalVmVerifierPvs::<u8>::width()];
        *v.as_mut_slice().borrow_mut() = self;
        v
    }
}

impl<F: PrimeField32> InternalVmVerifierExtraPvs<Felt<F>> {
    pub fn uninit<C: Config<F = F>>(builder: &mut Builder<C>) -> Self {
        Self {
            leaf_verifier_commit: array::from_fn(|_| builder.uninit()),
            internal_program_commit: array::from_fn(|_| builder.uninit()),
        }
    }
}

impl<F: Default + Clone> InternalVmVerifierExtraPvs<Felt<F>> {
    pub fn flatten(self) -> Vec<Felt<F>> {
        let mut v = vec![Felt(0, Default::default()); InternalVmVerifierExtraPvs::<u8>::width()];
        *v.as_mut_slice().borrow_mut() = self;
        v
    }
}
