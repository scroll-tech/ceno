#[cfg(not(feature = "u16limb_circuit"))]
mod jal;
#[cfg(feature = "u16limb_circuit")]
mod jal_v2;

#[cfg(not(feature = "u16limb_circuit"))]
mod jalr;
#[cfg(feature = "u16limb_circuit")]
mod jalr_v2;

#[cfg(not(feature = "u16limb_circuit"))]
pub use jal::JalInstruction;
#[cfg(feature = "u16limb_circuit")]
pub use jal_v2::JalInstruction;

#[cfg(not(feature = "u16limb_circuit"))]
pub use jalr::JalrInstruction;
#[cfg(feature = "u16limb_circuit")]
pub use jalr_v2::JalrInstruction;

#[cfg(test)]
mod test;
