// TODO: rename and restructure

use crate::chip_handler_new::rom_handler::ROMHandler;
use crate::constants::OpcodeType;
use crate::structs::ROMType;
use ark_std::iterable::Iterable;
use ff_ext::ExtensionField;
use itertools::Itertools;
use simple_frontend::structs::{Cell, CellId, CircuitBuilder, MixedCell};

struct BytecodeChip {}

impl BytecodeChip {
    // TODO: rename and document
    fn bytecode_with_pc_opcode<Ext: ExtensionField>(
        rom_handler: &mut ROMHandler<Ext>,
        circuit_builder: &mut CircuitBuilder<Ext>,
        pc: &[CellId],
        opcode: OpcodeType,
    ) {
        let key = [
            vec![MixedCell::Constant(Ext::BaseField::from(
                ROMType::Bytecode as u64,
            ))],
            pc.iter().map(|&x| x.into()).collect_vec(),
        ]
        .concat();

        rom_handler.read_mixed(
            circuit_builder,
            &key,
            &[MixedCell::Constant(Ext::BaseField::from(opcode as u64))],
        );
    }

    // TODO: rename and document
    fn bytecode_with_pc_byte<Ext: ExtensionField>(
        rom_handler: &mut ROMHandler<Ext>,
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
        rom_handler.read_mixed(circuit_builder, &key, &[byte.into()]);
    }
}
