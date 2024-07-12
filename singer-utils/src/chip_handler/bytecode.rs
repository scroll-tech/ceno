use ff_ext::ExtensionField;
use itertools::Itertools;
use simple_frontend::structs::{CellId, CircuitBuilder, MixedCell};

use crate::{
    constants::OpcodeType,
    structs::{ROMHandler, ROMType},
};

use super::{BytecodeChipOperations, ROMOperations};

impl<Ext: ExtensionField> ROMHandler<Ext> {
    pub fn bytecode_with_pc(
        &mut self,
        circuit_builder: &mut CircuitBuilder<Ext>,
        pc: &[CellId],
        opcode: u64,
    ) {
        let key = [
            vec![MixedCell::Constant(Ext::BaseField::from(
                ROMType::Bytecode as u64,
            ))],
            pc.iter().map(|&x| x.into()).collect_vec(),
        ]
        .concat();
        self.rom_load_mixed(
            circuit_builder,
            &key,
            &[MixedCell::Constant(Ext::BaseField::from(opcode))],
        );
    }
}

impl<Ext: ExtensionField> BytecodeChipOperations<Ext> for ROMHandler<Ext> {
    fn bytecode_with_pc_opcode(
        &mut self,
        circuit_builder: &mut CircuitBuilder<Ext>,
        pc: &[CellId],
        opcode: OpcodeType,
    ) {
        self.bytecode_with_pc(circuit_builder, pc, opcode.into());
    }

    fn bytecode_with_pc_byte(
        &mut self,
        circuit_builder: &mut CircuitBuilder<Ext>,
        pc: &[CellId],
        byte: CellId,
    ) {
        let key = [
            vec![MixedCell::Constant(Ext::BaseField::from(
                ROMType::Bytecode as u64,
            ))],
            pc.iter().map(|&x| x.into()).collect_vec(),
        ]
        .concat();
        self.rom_load_mixed(circuit_builder, &key, &[byte.into()]);
    }
}
