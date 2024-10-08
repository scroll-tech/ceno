use super::RIVInstruction;

mod shift_imm_circuit;

#[cfg(test)]
mod test;

pub struct SrliOp;

impl RIVInstruction for SrliOp {
    const INST_KIND: ceno_emul::InsnKind = ceno_emul::InsnKind::SRLI;
}
