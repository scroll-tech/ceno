//! Narrow, process-local attribution for symbolic circuit setup.
//!
//! This records only static GKR layer compilation, whose dominant operation is
//! expression-to-monomial conversion.  It is intentionally opt-in at the
//! caller: normal proving code pays one relaxed atomic increment per layer.

use std::sync::atomic::{AtomicU64, Ordering};

static STATIC_LAYER_BUILD_NS: AtomicU64 = AtomicU64::new(0);
static SELECTOR_MONOMIALIZE_NS: AtomicU64 = AtomicU64::new(0);
static MAIN_MONOMIALIZE_NS: AtomicU64 = AtomicU64::new(0);
static MAIN_MONOMIAL_EXTRACT_NS: AtomicU64 = AtomicU64::new(0);
static MAIN_MONOMIAL_FINALIZE_NS: AtomicU64 = AtomicU64::new(0);

pub fn reset() {
    STATIC_LAYER_BUILD_NS.store(0, Ordering::Relaxed);
    SELECTOR_MONOMIALIZE_NS.store(0, Ordering::Relaxed);
    MAIN_MONOMIALIZE_NS.store(0, Ordering::Relaxed);
    MAIN_MONOMIAL_EXTRACT_NS.store(0, Ordering::Relaxed);
    MAIN_MONOMIAL_FINALIZE_NS.store(0, Ordering::Relaxed);
}

pub fn static_layer_build_ns() -> u64 {
    STATIC_LAYER_BUILD_NS.load(Ordering::Relaxed)
}

pub fn selector_monomialize_ns() -> u64 {
    SELECTOR_MONOMIALIZE_NS.load(Ordering::Relaxed)
}

pub fn main_monomialize_ns() -> u64 {
    MAIN_MONOMIALIZE_NS.load(Ordering::Relaxed)
}

pub fn main_monomial_extract_ns() -> u64 {
    MAIN_MONOMIAL_EXTRACT_NS.load(Ordering::Relaxed)
}

pub fn main_monomial_finalize_ns() -> u64 {
    MAIN_MONOMIAL_FINALIZE_NS.load(Ordering::Relaxed)
}

pub fn record_static_layer_build_ns(nanos: u64) {
    STATIC_LAYER_BUILD_NS.fetch_add(nanos, Ordering::Relaxed);
}

pub fn record_selector_monomialize_ns(nanos: u64) {
    SELECTOR_MONOMIALIZE_NS.fetch_add(nanos, Ordering::Relaxed);
}

pub fn record_main_monomialize_ns(nanos: u64) {
    MAIN_MONOMIALIZE_NS.fetch_add(nanos, Ordering::Relaxed);
}

pub fn record_main_monomial_extract_ns(nanos: u64) {
    MAIN_MONOMIAL_EXTRACT_NS.fetch_add(nanos, Ordering::Relaxed);
}

pub fn record_main_monomial_finalize_ns(nanos: u64) {
    MAIN_MONOMIAL_FINALIZE_NS.fetch_add(nanos, Ordering::Relaxed);
}
