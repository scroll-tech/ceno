mod auipc;
mod jal;
mod lui;

pub use auipc::AuipcInstruction;
pub use jal::JalInstruction;
pub use lui::LuiInstruction;

#[cfg(test)]
mod test;
