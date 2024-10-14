use crate::{
    chip_handler::{util::cell_to_mixed, ChipHandler},
    constants::OpcodeType,
    structs::ROMType,
};
use ff_ext::ExtensionField;
use simple_frontend::structs::{CellId, CircuitBuilder, MixedCell};

pub struct BytecodeChip {}

impl BytecodeChip {
    pub fn bytecode_with_pc_opcode<Ext: ExtensionField>(
        chip_handler: &mut ChipHandler<Ext>,
        circuit_builder: &mut CircuitBuilder<Ext>,
        pc: &[CellId],
        opcode: OpcodeType,
    ) {
        let key = [
            vec![MixedCell::Constant(Ext::BaseField::from(
                ROMType::Bytecode as u64,
            ))],
            cell_to_mixed(pc),
        ]
        .concat();

        chip_handler.rom_handler.read_mixed(
            circuit_builder,
            &key,
            &[MixedCell::Constant(Ext::BaseField::from(opcode as u64))],
        );
    }

    pub fn bytecode_with_pc_byte<Ext: ExtensionField>(
        chip_handler: &mut ChipHandler<Ext>,
        circuit_builder: &mut CircuitBuilder<Ext>,
        pc: &[CellId],
        byte: CellId,
    ) {
        let key = [
            vec![MixedCell::Constant(Ext::BaseField::from(
                ROMType::Bytecode as u64,
            ))],
            cell_to_mixed(pc),
        ]
        .concat();
        chip_handler
            .rom_handler
            .read_mixed(circuit_builder, &key, &[byte.into()]);
    }
}
