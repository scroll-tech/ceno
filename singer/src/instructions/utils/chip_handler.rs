use frontend::structs::{CellId, CircuitBuilder, ConstantType, MixedCell, WireId};
use goldilocks::SmallField;

use crate::{
    constants::{OpcodeType, RANGE_CHIP_BIT_WIDTH, STACK_TOP_BIT_WIDTH, VALUE_BIT_WIDTH},
    error::ZKVMError,
    instructions::ChipChallenges,
};

use super::{i64_to_field, uint::UIntAddSub, ChipHandler, PCUInt, TSUInt, UInt};

impl ChipHandler {
    pub(in crate::instructions) fn new<F: SmallField>(
        circuit_builder: &mut CircuitBuilder<F>,
        size: usize,
    ) -> Self {
        let (wire_out_id, records) = circuit_builder.create_wire_out(size);
        Self {
            wire_out_id,
            records,
            count: 0,
        }
    }

    pub(in crate::instructions) fn wire_out_id(&self) -> WireId {
        self.wire_out_id
    }

    /// Pad th remaining cells with constants.
    pub(in crate::instructions) fn finalize_with_const_pad<F: SmallField>(
        &self,
        circuit_builder: &mut CircuitBuilder<F>,
        constant: &F,
    ) {
        for i in self.count..self.records.len() {
            circuit_builder.add_const(self.records[i], ConstantType::Field(*constant));
        }
    }

    /// Pad th remaining cells with the last one.
    pub(in crate::instructions) fn finalize_with_repeated_last<F: SmallField>(
        &self,
        circuit_builder: &mut CircuitBuilder<F>,
    ) {
        for i in self.count..self.records.len() {
            circuit_builder.add(
                self.records[i],
                self.records[self.count - 1],
                ConstantType::Field(F::ONE),
            );
        }
    }

    pub(in crate::instructions) fn state_in<F: SmallField>(
        &mut self,
        circuit_builder: &mut CircuitBuilder<F>,
        pc: &[CellId],
        stack_ts: &[CellId],
        memory_ts: &[CellId],
        stack_top: CellId,
        clk: CellId,
        challenges: &ChipChallenges,
    ) {
        let pc_rlc = if pc.len() == 1 {
            pc[0]
        } else {
            let pc_rlc = circuit_builder.create_cell();
            circuit_builder.rlc(pc_rlc, pc, challenges.record_item_rlc());
            pc_rlc
        };
        let stack_ts_rlc = if stack_ts.len() == 1 {
            stack_ts[0]
        } else {
            let stack_ts_rlc = circuit_builder.create_cell();
            circuit_builder.rlc(stack_ts_rlc, stack_ts, challenges.record_item_rlc());
            stack_ts_rlc
        };
        let memory_ts_rlc = if memory_ts.len() == 1 {
            memory_ts[0]
        } else {
            let memory_ts_rlc = circuit_builder.create_cell();
            circuit_builder.rlc(memory_ts_rlc, memory_ts, challenges.record_item_rlc());
            memory_ts_rlc
        };
        circuit_builder.rlc(
            self.records[self.count],
            &[pc_rlc, stack_ts_rlc, memory_ts_rlc, stack_top, clk],
            challenges.global_state(),
        );

        self.count += 1;
    }

    pub(in crate::instructions) fn add_pc_const<F: SmallField>(
        circuit_builder: &mut CircuitBuilder<F>,
        pc: &PCUInt,
        constant: i64,
        witness: &[CellId],
    ) -> Result<PCUInt, ZKVMError> {
        let carry = UIntAddSub::<PCUInt>::extract_unsafe_carry(witness);
        UIntAddSub::<PCUInt>::add_const_unsafe(circuit_builder, &pc, &i64_to_field(constant), carry)
    }

    pub(in crate::instructions) fn add_ts_with_const<F: SmallField>(
        &mut self,
        circuit_builder: &mut CircuitBuilder<F>,
        ts: &TSUInt,
        constant: i64,
        witness: &[CellId],
    ) -> Result<TSUInt, ZKVMError> {
        let carry = UIntAddSub::<TSUInt>::extract_unsafe_carry(witness);
        UIntAddSub::<TSUInt>::add_const(circuit_builder, self, &ts, &i64_to_field(constant), carry)
    }

    pub(in crate::instructions) fn state_out<F: SmallField>(
        &mut self,
        circuit_builder: &mut CircuitBuilder<F>,
        pc: &[CellId],
        stack_ts: &[CellId],
        memory_ts: &[CellId],
        stack_top: MixedCell<F>,
        clk: MixedCell<F>,
        challenges: &ChipChallenges,
    ) {
        let pc_rlc = if pc.len() == 1 {
            pc[0]
        } else {
            let pc_rlc = circuit_builder.create_cell();
            circuit_builder.rlc(pc_rlc, pc, challenges.record_item_rlc());
            pc_rlc
        };
        let stack_ts_rlc = if stack_ts.len() == 1 {
            stack_ts[0]
        } else {
            let stack_ts_rlc = circuit_builder.create_cell();
            circuit_builder.rlc(stack_ts_rlc, stack_ts, challenges.record_item_rlc());
            stack_ts_rlc
        };
        let memory_ts_rlc = if memory_ts.len() == 1 {
            memory_ts[0]
        } else {
            let memory_ts_rlc = circuit_builder.create_cell();
            circuit_builder.rlc(memory_ts_rlc, memory_ts, challenges.record_item_rlc());
            memory_ts_rlc
        };
        circuit_builder.rlc_mixed(
            self.records[self.count],
            &[
                pc_rlc.into(),
                stack_ts_rlc.into(),
                memory_ts_rlc.into(),
                stack_top,
                clk,
            ],
            challenges.global_state(),
        );

        self.count += 1;
    }

    pub(in crate::instructions) fn bytecode_with_pc_opcode<F: SmallField>(
        &mut self,
        circuit_builder: &mut CircuitBuilder<F>,
        pc: &[CellId],
        opcode: OpcodeType,
        challenges: &ChipChallenges,
    ) {
        let pc_rlc = circuit_builder.create_cell();
        circuit_builder.rlc(pc_rlc, pc, challenges.record_item_rlc());
        circuit_builder.rlc_mixed(
            self.records[self.count],
            &[pc_rlc.into(), MixedCell::Constant(F::from(opcode as u64))],
            challenges.bytecode(),
        );

        self.count += 1;
    }

    pub(in crate::instructions) fn bytecode_with_pc_byte<F: SmallField>(
        &mut self,
        circuit_builder: &mut CircuitBuilder<F>,
        pc: &[CellId],
        byte: CellId,
        challenges: &ChipChallenges,
    ) {
        let pc_rlc = circuit_builder.create_cell();
        circuit_builder.rlc(pc_rlc, pc, challenges.record_item_rlc());
        circuit_builder.rlc(
            self.records[self.count],
            &[pc_rlc, byte],
            challenges.bytecode(),
        );

        self.count += 1;
    }

    pub(in crate::instructions) fn stack_push_values<F: SmallField>(
        &mut self,
        circuit_builder: &mut CircuitBuilder<F>,
        stack_top: MixedCell<F>,
        stack_ts: &[CellId],
        values: &[CellId],
        challenges: &ChipChallenges,
    ) {
        let stack_ts_rlc = if stack_ts.len() == 1 {
            stack_ts[0]
        } else {
            let stack_ts_rlc = circuit_builder.create_cell();
            circuit_builder.rlc(stack_ts_rlc, stack_ts, challenges.record_item_rlc());
            stack_ts_rlc
        };
        let value_rlc = circuit_builder.create_cell();
        circuit_builder.rlc(value_rlc, values, challenges.record_item_rlc());
        circuit_builder.rlc_mixed(
            self.records[self.count],
            &[stack_top, stack_ts_rlc.into(), value_rlc.into()],
            challenges.stack(),
        );

        self.count += 1;
    }

    pub(in crate::instructions) fn stack_push_rlc<F: SmallField>(
        &mut self,
        circuit_builder: &mut CircuitBuilder<F>,
        stack_top: MixedCell<F>,
        stack_ts: &[CellId],
        rlc: CellId,
        challenges: &ChipChallenges,
    ) {
        let stack_ts_rlc = if stack_ts.len() == 1 {
            stack_ts[0]
        } else {
            let stack_ts_rlc = circuit_builder.create_cell();
            circuit_builder.rlc(stack_ts_rlc, stack_ts, challenges.record_item_rlc());
            stack_ts_rlc
        };
        circuit_builder.rlc_mixed(
            self.records[self.count],
            &[stack_top, stack_ts_rlc.into(), rlc.into()],
            challenges.stack(),
        );

        self.count += 1;
    }

    pub(in crate::instructions) fn stack_pop_values<F: SmallField>(
        &mut self,
        circuit_builder: &mut CircuitBuilder<F>,
        stack_top: MixedCell<F>,
        stack_ts: &[CellId],
        values: &[CellId],
        challenges: &ChipChallenges,
    ) {
        let stack_ts_rlc = if stack_ts.len() == 1 {
            stack_ts[0]
        } else {
            let stack_ts_rlc = circuit_builder.create_cell();
            circuit_builder.rlc(stack_ts_rlc, stack_ts, challenges.record_item_rlc());
            stack_ts_rlc
        };
        let value_rlc = circuit_builder.create_cell();
        circuit_builder.rlc(value_rlc, values, challenges.record_item_rlc());
        circuit_builder.rlc_mixed(
            self.records[self.count],
            &[stack_top, stack_ts_rlc.into(), value_rlc.into()],
            challenges.stack(),
        );

        self.count += 1;
    }

    pub(in crate::instructions) fn stack_pop_rlc<F: SmallField>(
        &mut self,
        circuit_builder: &mut CircuitBuilder<F>,
        stack_top: MixedCell<F>,
        stack_ts: &[CellId],
        rlc: CellId,
        challenges: &ChipChallenges,
    ) {
        let stack_ts_rlc = if stack_ts.len() == 1 {
            stack_ts[0]
        } else {
            let stack_ts_rlc = circuit_builder.create_cell();
            circuit_builder.rlc(stack_ts_rlc, stack_ts, challenges.record_item_rlc());
            stack_ts_rlc
        };
        circuit_builder.rlc_mixed(
            self.records[self.count],
            &[stack_top, stack_ts_rlc.into(), rlc.into()],
            challenges.stack(),
        );

        self.count += 1;
    }

    pub(in crate::instructions) fn range_check_stack_top<F: SmallField>(
        &mut self,
        circuit_builder: &mut CircuitBuilder<F>,
        stack_top: MixedCell<F>,
    ) -> Result<(), ZKVMError> {
        self.small_range_check(circuit_builder, stack_top, STACK_TOP_BIT_WIDTH)
    }

    // /// Check the range of stack values within [0, 1 << STACK_VALUE_BYTE_WIDTH * 8).
    // /// Return the verified values.
    // pub(in crate::instructions) fn range_check_stack_values<F: SmallField>(
    //     &mut self,
    //     circuit_builder: &mut CircuitBuilder<F>,
    //     values: &[CellId],
    //     range_value_witness: Option<&[CellId]>,
    // ) -> Result<Vec<CellId>, ZKVMError> {
    //     let value = StackUInt::try_from(values)?;
    //     let result = self.range_check_uint(circuit_builder, &value, range_value_witness)?;
    //     Ok(result.values)
    // }

    /// Check the range of stack values within [0, 1 << STACK_VALUE_BYTE_WIDTH * 8).
    /// Return the verified values.
    pub(in crate::instructions) fn range_check_uint<F, const M: usize, const C: usize>(
        &mut self,
        circuit_builder: &mut CircuitBuilder<F>,
        uint: &UInt<M, C>,
        range_value_witness: Option<&[CellId]>,
    ) -> Result<UInt<M, C>, ZKVMError>
    where
        F: SmallField,
    {
        let n_cell = (M + C - 1) / C;
        if C <= RANGE_CHIP_BIT_WIDTH {
            for value in uint.values.iter().take(n_cell - 1) {
                self.small_range_check(circuit_builder, (*value).into(), VALUE_BIT_WIDTH)?;
            }
            self.small_range_check(circuit_builder, uint.values[n_cell - 1].into(), M % C)?;
            Ok((*uint).clone())
        } else if let Some(range_values) = range_value_witness {
            let range_value = UInt::<M, C>::from_range_values(circuit_builder, range_values)?;
            uint.assert_eq(circuit_builder, &range_value);
            let b: usize = M.min(C);
            let chunk_size = (b + RANGE_CHIP_BIT_WIDTH - 1) / RANGE_CHIP_BIT_WIDTH;
            for chunk in range_values.chunks(chunk_size) {
                for i in 0..chunk_size - 1 {
                    self.small_range_check(circuit_builder, chunk[i].into(), RANGE_CHIP_BIT_WIDTH)?;
                }
                self.small_range_check(
                    circuit_builder,
                    chunk[chunk_size - 1].into(),
                    b - (chunk_size - 1) * RANGE_CHIP_BIT_WIDTH,
                )?;
            }
            Ok(range_value)
        } else {
            Err(ZKVMError::CircuitError)
        }
    }

    // pub(in crate::instructions) fn range_check_bytes<F: SmallField>(
    //     &mut self,
    //     circuit_builder: &mut CircuitBuilder<F>,
    //     bytes: &[CellId],
    // ) -> Result<(), ZKVMError> {
    //     for byte in bytes {
    //         self.small_range_check(circuit_builder, (*byte).into(), 8)?;
    //     }
    //     Ok(())
    // }

    // pub(in crate::instructions) fn range_check_bit<F: SmallField>(
    //     &mut self,
    //     circuit_builder: &mut CircuitBuilder<F>,
    //     bit: CellId,
    // ) -> Result<(), ZKVMError> {
    //     self.small_range_check(circuit_builder, bit.into(), 1)
    // }

    pub(in crate::instructions) fn mem_load<F: SmallField>(
        &mut self,
        circuit_builder: &mut CircuitBuilder<F>,
        offset: &[CellId],
        memory_ts: &[CellId],
        byte: CellId,
        challenges: &ChipChallenges,
    ) {
        let offset_rlc = if offset.len() == 1 {
            offset[0]
        } else {
            let offset_rlc = circuit_builder.create_cell();
            circuit_builder.rlc(offset_rlc, offset, challenges.record_item_rlc());
            offset_rlc
        };
        let memory_ts_rlc = if memory_ts.len() == 1 {
            memory_ts[0]
        } else {
            let memory_ts_rlc = circuit_builder.create_cell();
            circuit_builder.rlc(memory_ts_rlc, memory_ts, challenges.record_item_rlc());
            memory_ts_rlc
        };
        circuit_builder.rlc(
            self.records[self.count],
            &[offset_rlc, memory_ts_rlc, byte],
            challenges.mem(),
        );

        self.count += 1;
    }

    pub(in crate::instructions) fn mem_store<F: SmallField>(
        &mut self,
        circuit_builder: &mut CircuitBuilder<F>,
        offset: &[CellId],
        memory_ts: &[CellId],
        byte: CellId,
        challenges: &ChipChallenges,
    ) {
        let offset_rlc = if offset.len() == 1 {
            offset[0]
        } else {
            let offset_rlc = circuit_builder.create_cell();
            circuit_builder.rlc(offset_rlc, offset, challenges.record_item_rlc());
            offset_rlc
        };
        let memory_ts_rlc = if memory_ts.len() == 1 {
            memory_ts[0]
        } else {
            let memory_ts_rlc = circuit_builder.create_cell();
            circuit_builder.rlc(memory_ts_rlc, memory_ts, challenges.record_item_rlc());
            memory_ts_rlc
        };
        circuit_builder.rlc(
            self.records[self.count],
            &[offset_rlc, memory_ts_rlc, byte],
            challenges.mem(),
        );

        self.count += 1;
    }

    pub(in crate::instructions) fn calldataload_rlc<F: SmallField>(
        &mut self,
        circuit_builder: &mut CircuitBuilder<F>,
        offset: &[CellId],
        data_rlc: CellId,
        challenges: &ChipChallenges,
    ) {
        circuit_builder.rlc(
            self.records[self.count],
            &[offset, &[data_rlc]].concat(),
            challenges.calldata(),
        );

        self.count += 1;
    }

    fn small_range_check<F: SmallField>(
        &mut self,
        circuit_builder: &mut CircuitBuilder<F>,
        value: MixedCell<F>,
        bit_width: usize,
    ) -> Result<(), ZKVMError> {
        if bit_width > RANGE_CHIP_BIT_WIDTH {
            return Err(ZKVMError::CircuitError);
        }
        circuit_builder.add_cell_expr(
            self.records[self.count],
            &value.mul(F::from(1 << (RANGE_CHIP_BIT_WIDTH - bit_width))),
        );
        self.count += 1;
        Ok(())
    }
}
