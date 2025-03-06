use std::{borrow::Borrow, marker::PhantomData, sync::atomic::AtomicUsize};

use ff_ext::ExtensionField;
use lazy_static::lazy_static;
use p3_commit::Mmcs;
use rand::RngCore;

pub trait MerkleConfig<E: ExtensionField> {
    type Mmcs: Mmcs;
}

pub struct MerkleTree<M, E: ExtensionField, Config: MerkleConfig<E>> {
    pub mmcs: <Config::Mmcs as Mmcs<E>>::ProverData<M>,
}

pub struct MultiPath<E: ExtensionField, Config: MerkleConfig<E>> {
    pub path: <Config::Mmcs as Mmcs<E>>::Proof,
}

#[derive(Debug, Default)]
pub struct HashCounter {
    counter: AtomicUsize,
}

lazy_static! {
    static ref HASH_COUNTER: HashCounter = HashCounter::default();
}

impl HashCounter {
    pub(crate) fn add() -> usize {
        HASH_COUNTER
            .counter
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst)
    }

    pub fn reset() {
        HASH_COUNTER
            .counter
            .store(0, std::sync::atomic::Ordering::SeqCst)
    }

    pub fn get() -> usize {
        HASH_COUNTER
            .counter
            .load(std::sync::atomic::Ordering::SeqCst)
    }
}
