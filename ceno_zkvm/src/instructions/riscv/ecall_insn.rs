use crate::{
    chip_handler::{GlobalStateRegisterMachineChipOperations, RegisterChipOperations},
    circuit_builder::CircuitBuilder,
    error::ZKVMError,
    expression::{ToExpr, WitIn},
    instructions::riscv::config::ExprLtConfig,
    tables::InsnRecord,
};
use ceno_emul::InsnKind::EANY;
use ff_ext::ExtensionField;

const X5: usize = 5;
const X10: usize = 10;
const X11: usize = 11;

pub struct EcallInstructionConfig {
    pub pc: WitIn,
    pub ts: WitIn,
    prev_x5_ts: WitIn,
    lt_x5_cfg: ExprLtConfig,
    prev_x10_ts: WitIn,
    lt_x10_cfg: ExprLtConfig,
    // prev_x11_ts: WitIn,
    // lt_x11_cfg: ExprLtConfig,
}

impl EcallInstructionConfig {
    pub fn construct_circuit<E: ExtensionField>(
        cb: &mut CircuitBuilder<E>,
    ) -> Result<Self, ZKVMError> {
        let pc = cb.create_witin(|| "pc")?;
        let ts = cb.create_witin(|| "cur_ts")?;

        cb.state_in(pc.expr(), ts.expr())?;

        cb.lk_fetch(&InsnRecord::new(
            pc.expr(),
            (EANY.codes().opcode as usize).into(),
            0.into(),
            (EANY.codes().func3 as usize).into(),
            0.into(),
            0.into(),
            0.into(),
        ))?;

        let prev_x5_ts = cb.create_witin(|| "prev_x5_ts")?;
        let prev_x10_ts = cb.create_witin(|| "prev_x10_ts")?;

        let (_, lt_x5_cfg) = cb.register_read(
            || "read x5",
            X5.into(),
            prev_x5_ts.expr(),
            ts.expr(),
            &[], // TODO
        )?;

        let (_, lt_x10_cfg) = cb.register_read(
            || "read x10",
            X10.into(),
            prev_x10_ts.expr(),
            ts.expr(),
            &[], // TODO
        )?;

        Ok(Self {
            pc,
            ts,
            prev_x5_ts,
            prev_x10_ts,
            lt_x5_cfg,
            lt_x10_cfg,
        })
    }

    pub fn assign_instances(&self) -> Result<(), ZKVMError> {
        Ok(())
    }
}
