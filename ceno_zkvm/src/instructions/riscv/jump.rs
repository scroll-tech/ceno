#[cfg(not(feature = "u16limb_circuit"))]
mod jal;
#[cfg(feature = "u16limb_circuit")]
mod jal_lui_v2;

mod jalr;

#[cfg(not(feature = "u16limb_circuit"))]
pub use jal::JalInstruction;

#[cfg(feature = "u16limb_circuit")]
pub use jal_lui_v2::JalInstruction;

pub use jalr::JalrInstruction;

#[cfg(test)]
mod test;
