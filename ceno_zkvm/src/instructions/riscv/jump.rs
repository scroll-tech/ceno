mod auipc;
mod jal;
mod jalr;
mod lui;

pub use auipc::AuipcInstruction;
pub use jal::JalInstruction;
pub use jalr::JalrInstruction;
pub use lui::LuiInstruction;

#[cfg(test)]
mod test;
