mod gadget;
pub mod load;
pub mod store;

#[cfg(test)]
mod test;

pub use load::LwInstruction;
#[cfg(test)]
pub use store::{SbInstruction, ShInstruction, SwInstruction};
