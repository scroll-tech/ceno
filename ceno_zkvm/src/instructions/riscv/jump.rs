mod jal;
mod jalr;

pub use jal::JalInstruction;
pub use jalr::JalrInstruction;

#[cfg(test)]
mod test;
