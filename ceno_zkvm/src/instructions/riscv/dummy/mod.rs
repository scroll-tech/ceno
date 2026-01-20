//! Helper dummy circuits for testing and large ECALLs.

mod dummy_circuit;
pub use dummy_circuit::DummyConfig;

mod dummy_ecall;
pub use dummy_ecall::LargeEcallDummy;

#[cfg(test)]
mod test;
