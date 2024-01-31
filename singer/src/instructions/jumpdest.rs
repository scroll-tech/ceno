use std::sync::Arc;

use frontend::structs::{CircuitBuilder, MixedCell};
use gkr::structs::Circuit;
use goldilocks::SmallField;
use revm_interpreter::Record;

use crate::instructions::InstCircuitLayout;
use crate::{constants::OpcodeType, error::ZKVMError};
use crate::{CircuitWiresIn, PrepareSingerWiresIn, SingerWiresIn};

use super::utils::uint::{u2fvec, UIntAddSub};
use super::utils::TSUInt;
use super::InstructionGraph;
use super::{
    utils::{ChipHandler, PCUInt},
    ChipChallenges, InstCircuit, InstOutputType, Instruction,
};

pub struct JumpdestInstruction;

impl InstructionGraph for JumpdestInstruction {
    type InstType = Self;
}

register_wires_in!(
    JumpdestInstruction,
    phase0_size {
        phase0_pc => PCUInt::N_OPRAND_CELLS ,
        phase0_stack_top => 1,
        phase0_clk => 1,

        phase0_pc_add => UIntAddSub::<PCUInt>::N_NO_OVERFLOW_WITNESS_UNSAFE_CELLS
    },
    phase1_size {
        phase1_stack_ts_rlc => 1,
        phase1_memory_ts_rlc => 1
    }
);

register_wires_out!(
    JumpdestInstruction,
    global_state_in_size {
        state_in => 1
    },
    global_state_out_size {
        state_out => 1
    },
    bytecode_chip_size {
        current => 1
    }
);

impl JumpdestInstruction {
    pub const OPCODE: OpcodeType = OpcodeType::JUMPDEST;
}

impl Instruction for JumpdestInstruction {
    #[inline]
    fn witness_size(phase: usize) -> usize {
        match phase {
            0 => Self::phase0_size(),
            1 => Self::phase1_size(),
            _ => 0,
        }
    }

    fn output_size(inst_out: InstOutputType) -> usize {
        match inst_out {
            InstOutputType::GlobalStateIn => Self::global_state_in_size(),
            InstOutputType::GlobalStateOut => Self::global_state_out_size(),
            InstOutputType::BytecodeChip => Self::bytecode_chip_size(),
            _ => 0,
        }
    }

    fn construct_circuit<F: SmallField>(
        challenges: ChipChallenges,
    ) -> Result<InstCircuit<F>, ZKVMError> {
        let mut circuit_builder = CircuitBuilder::new();
        let (phase0_wire_id, phase0) = circuit_builder.create_wire_in(Self::phase0_size());
        let (phase1_wire_id, phase1) = circuit_builder.create_wire_in(Self::phase1_size());
        let mut global_state_in_handler = ChipHandler::new(
            &mut circuit_builder,
            challenges,
            Self::global_state_in_size(),
        );
        let mut global_state_out_handler = ChipHandler::new(
            &mut circuit_builder,
            challenges,
            Self::global_state_out_size(),
        );
        let mut bytecode_chip_handler =
            ChipHandler::new(&mut circuit_builder, challenges, Self::bytecode_chip_size());

        // State update
        let pc = PCUInt::try_from(&phase0[Self::phase0_pc()])?;
        let stack_ts_rlc = phase1[Self::phase1_stack_ts_rlc().start];
        let memory_ts_rlc = phase1[Self::phase1_memory_ts_rlc().start];
        let stack_top = phase0[Self::phase0_stack_top().start];
        let clk = phase0[Self::phase0_clk().start];
        let clk_expr = MixedCell::Cell(clk);
        global_state_in_handler.state_in(
            &mut circuit_builder,
            pc.values(),
            &[stack_ts_rlc],
            &[memory_ts_rlc],
            stack_top,
            clk,
        );

        let next_pc = ChipHandler::add_pc_const(
            &mut circuit_builder,
            &pc,
            1,
            &phase0[Self::phase0_pc_add()],
        )?;
        global_state_out_handler.state_out(
            &mut circuit_builder,
            next_pc.values(),
            &[stack_ts_rlc], // Because there is no stack push.
            &[memory_ts_rlc],
            stack_top.into(),
            clk_expr.add(F::ONE),
        );

        // Bytecode check for (pc_rlc, jump)
        bytecode_chip_handler.bytecode_with_pc_opcode(
            &mut circuit_builder,
            pc.values(),
            Self::OPCODE,
        );

        global_state_in_handler.finalize_with_const_pad(&mut circuit_builder, &F::ONE);
        global_state_out_handler.finalize_with_const_pad(&mut circuit_builder, &F::ONE);
        bytecode_chip_handler.finalize_with_repeated_last(&mut circuit_builder);

        let outputs_wire_id = [
            Some(global_state_in_handler.wire_out_id()),
            Some(global_state_out_handler.wire_out_id()),
            Some(bytecode_chip_handler.wire_out_id()),
            None,
            None,
            None,
            None,
            None,
            None,
        ];

        circuit_builder.configure();
        Ok(InstCircuit {
            circuit: Arc::new(Circuit::new(&circuit_builder)),
            layout: InstCircuitLayout {
                chip_check_wire_id: outputs_wire_id,
                phases_wire_id: [Some(phase0_wire_id), Some(phase1_wire_id)],
                ..Default::default()
            },
        })
    }

    fn generate_pre_wires_in<F: SmallField>(record: &Record, index: usize) -> Option<Vec<F>> {
        match index {
            0 => {
                let mut wire_values = vec![F::ZERO; Self::phase0_size()];
                copy_pc_from_record!(wire_values, record);
                copy_stack_top_from_record!(wire_values, record);
                copy_clock_from_record!(wire_values, record);
                copy_pc_add_from_record!(wire_values, record);

                Some(wire_values)
            }
            1 => {
                let mut wire_values = vec![F::ZERO; TSUInt::N_OPRAND_CELLS];
                copy_memory_ts_from_record!(wire_values, record);
                Some(wire_values)
            }
            _ => None,
        }
    }
    fn complete_wires_in<F: SmallField>(
        pre_wires_in: &CircuitWiresIn<F>,
        _challenges: &Vec<F>,
    ) -> CircuitWiresIn<F> {
        // Currently the memory timestamp only takes one element, so no need to do anything
        // and no need to use the challenges.
        pre_wires_in.clone()
    }
}
