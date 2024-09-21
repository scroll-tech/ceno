use ff_ext::ExtensionField;
use crate::expression::WitIn;
use crate::instructions::riscv::config::ExprLtConfig;

pub struct IInstructionConfig<E: ExtensionField> {
    pc: WitIn,
    ts: WitIn,
    rs1_id: WitIn,
    rd_id: WitIn,
    prev_rs1_ts: WitIn,
    prev_rd_ts: WitIn,
    lt_rs1_cfg: ExprLtConfig,
    lt_prev_ts_cfg: ExprLtConfig,
}