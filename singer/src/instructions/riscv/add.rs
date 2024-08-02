use crate::error::ZKVMError;
use ff::Field;
use ff_ext::ExtensionField;
use gkr::structs::Circuit;
use paste::paste;
use simple_frontend::structs::{CircuitBuilder, MixedCell};
use singer_utils::{
    chip_handler::{GlobalStateChipOperations, OAMOperations, ROMOperations, RegisterChipOperations},
    constants::OpcodeType,
    register_witness,
    riscv_constant::RvInstructions,
    structs::{PCUInt, RAMHandler, ROMHandler, RegisterUInt, TSUInt, UInt64},
    uint::constants::AddSubConstants,
};
use std::{collections::BTreeMap, sync::Arc};

use super::super::{ChipChallenges, InstCircuit, InstCircuitLayout, Instruction, InstructionGraph};

pub struct AddInstruction;

impl<E: ExtensionField> InstructionGraph<E> for AddInstruction {
    type InstType = Self;
}

register_witness!(
    AddInstruction,
    phase0 {
        pc => PCUInt::N_OPERAND_CELLS,
        memory_ts => TSUInt::N_OPERAND_CELLS,
        clk => 1,

        rs1 => RegisterUInt::N_OPERAND_CELLS,
        rs2 => RegisterUInt::N_OPERAND_CELLS,
        rd => RegisterUInt::N_OPERAND_CELLS,

        next_pc => AddSubConstants::<PCUInt>::N_NO_OVERFLOW_WITNESS_UNSAFE_CELLS,
        next_memory_ts => AddSubConstants::<TSUInt>::N_WITNESS_CELLS_NO_CARRY_OVERFLOW,

        // instruction operation
        addend_0 => UInt64::N_OPERAND_CELLS,
        addend_1 => UInt64::N_OPERAND_CELLS,
        outcome => AddSubConstants::<UInt64>::N_WITNESS_CELLS,

        // the value pointed by `rd` before being written with `outcome`
        prev_rd_value => UInt64::N_OPERAND_CELLS,

        // register timestamps and comparison gadgets
        prev_rs1_ts => TSUInt::N_OPERAND_CELLS,
        prev_rs2_ts => TSUInt::N_OPERAND_CELLS,
        prev_rd_ts => TSUInt::N_OPERAND_CELLS,
        prev_rs1_ts_lt => AddSubConstants::<TSUInt>::N_WITNESS_CELLS,
        prev_rs2_ts_lt => AddSubConstants::<TSUInt>::N_WITNESS_CELLS,
        prev_rd_ts_lt => AddSubConstants::<TSUInt>::N_WITNESS_CELLS
    }
);

// TODO a workaround to keep the risc-v instruction
pub const RV_INSTRUCTION: RvInstructions = RvInstructions::ADD;
impl<E: ExtensionField> Instruction<E> for AddInstruction {
    // OPCODE is not used in RISC-V case, just for compatibility
    const OPCODE: OpcodeType = OpcodeType::RISCV;
    const NAME: &'static str = "ADD";
    fn construct_circuit(challenges: ChipChallenges) -> Result<InstCircuit<E>, ZKVMError> {
        let mut circuit_builder = CircuitBuilder::new();
        let (phase0_wire_id, phase0) = circuit_builder.create_witness_in(Self::phase0_size());
        let mut ram_handler = RAMHandler::new(&challenges);
        let mut rom_handler = ROMHandler::new(&challenges);

        let pc = PCUInt::try_from(&phase0[Self::phase0_pc()])?;
        let memory_ts = &phase0[Self::phase0_memory_ts()];
        let clk = phase0[Self::phase0_clk().start];
        let clk_expr = MixedCell::Cell(clk);
        let zero_cell_ids = [0];

        // Bytecode check for (pc, add)
        rom_handler.bytecode_with_pc(&mut circuit_builder, pc.values(), RV_INSTRUCTION.into());

        // State update
        ram_handler.state_in(
            &mut circuit_builder,
            pc.values(),
            &zero_cell_ids, // we don't have stack info here
            &memory_ts,
            0,
            clk,
        );

        let next_pc = ROMHandler::increase_pc(&mut circuit_builder, &pc, &phase0[Self::phase0_next_pc()])?;
        let next_memory_ts = rom_handler.increase_ts(
            &mut circuit_builder,
            &memory_ts.try_into()?,
            &phase0[Self::phase0_next_memory_ts()],
        )?;

        ram_handler.state_out(
            &mut circuit_builder,
            next_pc.values(),
            &zero_cell_ids,
            &next_memory_ts.values(),
            MixedCell::Cell(0),
            clk_expr.add(E::BaseField::ONE),
        );

        // Register timestamp range check
        let prev_rs1_ts = (&phase0[Self::phase0_prev_rs1_ts()]).try_into()?;
        let prev_rs2_ts = (&phase0[Self::phase0_prev_rs2_ts()]).try_into()?;
        let prev_rd_ts = (&phase0[Self::phase0_prev_rd_ts()]).try_into()?;
        let memory_ts = (&phase0[Self::phase0_memory_ts()]).try_into()?;
        TSUInt::assert_lt(
            &mut circuit_builder,
            &mut rom_handler,
            &prev_rs1_ts,
            &memory_ts,
            &phase0[Self::phase0_prev_rs1_ts_lt()],
        )?;
        TSUInt::assert_lt(
            &mut circuit_builder,
            &mut rom_handler,
            &prev_rs2_ts,
            &memory_ts,
            &phase0[Self::phase0_prev_rs2_ts_lt()],
        )?;
        TSUInt::assert_lt(
            &mut circuit_builder,
            &mut rom_handler,
            &prev_rd_ts,
            &memory_ts,
            &phase0[Self::phase0_prev_rd_ts_lt()],
        )?;
        if cfg!(feature = "dbg-opcode") {
            println!("addInstCircuit::phase0_outcome: {:?}", Self::phase0_outcome());
        }

        // Execution result = addend0 + addend1, with carry.
        let addend_0 = (&phase0[Self::phase0_addend_0()]).try_into()?;
        let addend_1 = (&phase0[Self::phase0_addend_1()]).try_into()?;
        let result = UInt64::add(
            &mut circuit_builder,
            &mut rom_handler,
            &addend_0,
            &addend_1,
            &phase0[Self::phase0_outcome()],
        )?;

        // Read/Write from registers
        let rs1 = &phase0[Self::phase0_rs1()];
        let rs2 = &phase0[Self::phase0_rs2()];
        let rd = &phase0[Self::phase0_rd()];
        let prev_rd_value = &phase0[Self::phase0_prev_rd_value()];
        ram_handler.register_load(
            &mut circuit_builder,
            rs1,
            prev_rs1_ts.values(),
            memory_ts.values(),
            &phase0[Self::phase0_addend_0()],
        );
        ram_handler.register_load(
            &mut circuit_builder,
            rs2,
            prev_rs2_ts.values(),
            memory_ts.values(),
            &phase0[Self::phase0_addend_1()],
        );
        ram_handler.register_store(
            &mut circuit_builder,
            rd,
            prev_rd_ts.values(),
            memory_ts.values(),
            &prev_rd_value,
            result.values(),
        );

        // Ram/Rom finalization
        let (ram_load_id, ram_store_id) = ram_handler.finalize(&mut circuit_builder);
        let rom_id = rom_handler.finalize(&mut circuit_builder);

        circuit_builder.configure();

        Ok(InstCircuit {
            circuit: Arc::new(Circuit::new(&circuit_builder)),
            layout: InstCircuitLayout {
                chip_check_wire_id: [ram_load_id, ram_store_id, rom_id],
                phases_wire_id: vec![phase0_wire_id],
                ..Default::default()
            },
        })
    }
}

#[cfg(test)]
mod test {
    use ark_std::test_rng;
    use ff::Field;
    use ff_ext::ExtensionField;
    use gkr::structs::LayerWitness;
    use goldilocks::{Goldilocks, GoldilocksExt2};
    use itertools::Itertools;
    use singer_utils::{
        constants::RANGE_CHIP_BIT_WIDTH,
        structs::{TSUInt, UInt64},
    };
    use std::{collections::BTreeMap, time::Instant};
    use transcript::Transcript;

    use crate::{
        instructions::{
            riscv::add::{AddInstruction, RV_INSTRUCTION},
            ChipChallenges, Instruction, InstructionGraph, SingerCircuitBuilder,
        },
        scheme::GKRGraphProverState,
        test::{get_uint_params, test_opcode_circuit_v2},
        utils::u64vec,
        CircuitWiresIn, SingerGraphBuilder, SingerParams,
    };

    #[test]
    fn test_add_construct_circuit() {
        let challenges = ChipChallenges::default();

        let phase0_idx_map = AddInstruction::phase0_idxes_map();
        let phase0_witness_size = AddInstruction::phase0_size();

        if cfg!(feature = "dbg-opcode") {
            println!("ADD: {:?}", &phase0_idx_map);
            println!("ADD witness_size: {:?}", phase0_witness_size);
        }

        // initialize general test inputs associated with push1
        let inst_circuit = AddInstruction::construct_circuit(challenges).unwrap();

        if cfg!(feature = "dbg-opcode") {
            println!("{:?}", inst_circuit.circuit.assert_consts);
        }

        let mut phase0_values_map = BTreeMap::<&'static str, Vec<Goldilocks>>::new();
        phase0_values_map.insert(AddInstruction::phase0_pc_str(), vec![Goldilocks::from(1u64)]);
        phase0_values_map.insert(AddInstruction::phase0_memory_ts_str(), vec![Goldilocks::from(3u64)]);
        phase0_values_map.insert(
            AddInstruction::phase0_next_memory_ts_str(),
            vec![
                // first TSUInt::N_RANGE_CELLS = 1*(48/16) = 3 cells are range values.
                // memory_ts + 1 = 4
                Goldilocks::from(4u64),
                Goldilocks::from(0u64),
                Goldilocks::from(0u64),
            ],
        );
        phase0_values_map.insert(AddInstruction::phase0_clk_str(), vec![Goldilocks::from(1u64)]);
        phase0_values_map.insert(
            AddInstruction::phase0_next_pc_str(),
            vec![], // carry is 0, may test carry using larger values in PCUInt
        );

        // register id assigned
        phase0_values_map.insert(AddInstruction::phase0_rs1_str(), vec![Goldilocks::from(1u64)]);
        phase0_values_map.insert(AddInstruction::phase0_rs2_str(), vec![Goldilocks::from(2u64)]);
        phase0_values_map.insert(AddInstruction::phase0_rd_str(), vec![Goldilocks::from(3u64)]);

        let m: u64 = (1 << get_uint_params::<UInt64>().1) - 1;
        phase0_values_map.insert(AddInstruction::phase0_addend_0_str(), vec![Goldilocks::from(m)]);
        phase0_values_map.insert(AddInstruction::phase0_addend_1_str(), vec![Goldilocks::from(1u64)]);
        let range_values = u64vec::<{ UInt64::N_RANGE_CELLS }, RANGE_CHIP_BIT_WIDTH>(m + 1);
        let mut wit_phase0_outcome: Vec<Goldilocks> = vec![];
        for i in 0..4 {
            wit_phase0_outcome.push(Goldilocks::from(range_values[i]))
        }
        wit_phase0_outcome.push(Goldilocks::from(1u64)); // carry is [1, 0, ...]
        phase0_values_map.insert(AddInstruction::phase0_outcome_str(), wit_phase0_outcome);

        phase0_values_map.insert(
            AddInstruction::phase0_prev_rd_value_str(),
            vec![Goldilocks::from(33u64)],
        );

        phase0_values_map.insert(AddInstruction::phase0_prev_rs1_ts_str(), vec![Goldilocks::from(2u64)]);
        let m: u64 = (1 << get_uint_params::<TSUInt>().1) - 1;
        let range_values = u64vec::<{ TSUInt::N_RANGE_CELLS }, RANGE_CHIP_BIT_WIDTH>(m);
        phase0_values_map.insert(
            AddInstruction::phase0_prev_rs1_ts_lt_str(),
            vec![
                Goldilocks::from(range_values[0]),
                Goldilocks::from(range_values[1]),
                Goldilocks::from(range_values[2]),
                Goldilocks::from(1u64), // borrow
            ],
        );
        phase0_values_map.insert(AddInstruction::phase0_prev_rs2_ts_str(), vec![Goldilocks::from(1u64)]);
        let m: u64 = (1 << get_uint_params::<TSUInt>().1) - 2;
        let range_values = u64vec::<{ TSUInt::N_RANGE_CELLS }, RANGE_CHIP_BIT_WIDTH>(m);
        phase0_values_map.insert(
            AddInstruction::phase0_prev_rs2_ts_lt_str(),
            vec![
                Goldilocks::from(range_values[0]),
                Goldilocks::from(range_values[1]),
                Goldilocks::from(range_values[2]),
                Goldilocks::from(1u64), // borrow
            ],
        );
        phase0_values_map.insert(AddInstruction::phase0_prev_rd_ts_str(), vec![Goldilocks::from(2u64)]);
        let m: u64 = (1 << get_uint_params::<TSUInt>().1) - 1;
        let range_values = u64vec::<{ TSUInt::N_RANGE_CELLS }, RANGE_CHIP_BIT_WIDTH>(m);
        phase0_values_map.insert(
            AddInstruction::phase0_prev_rd_ts_lt_str(),
            vec![
                Goldilocks::from(range_values[0]),
                Goldilocks::from(range_values[1]),
                Goldilocks::from(range_values[2]),
                Goldilocks::from(1u64), // borrow
            ],
        );
        // The actual challenges used is:
        // challenges
        //  { ChallengeConst { challenge: 1, exp: i }: [Goldilocks(c^i)] }
        let c = GoldilocksExt2::from(66u64);
        let circuit_witness_challenges = vec![c; 3];

        test_opcode_circuit_v2(
            &inst_circuit,
            &phase0_idx_map,
            phase0_witness_size,
            &phase0_values_map,
            circuit_witness_challenges,
        );
    }

    #[cfg(not(debug_assertions))]
    fn bench_add_instruction_helper<E: ExtensionField>(instance_num_vars: usize) {
        let chip_challenges = ChipChallenges::default();
        let circuit_builder = SingerCircuitBuilder::<E>::new_riscv(chip_challenges).expect("circuit builder failed");
        let mut singer_builder = SingerGraphBuilder::<E>::new();

        let mut rng = test_rng();
        let size = AddInstruction::phase0_size();
        let phase0: CircuitWiresIn<E::BaseField> = vec![LayerWitness {
            instances: (0..(1 << instance_num_vars))
                .map(|_| (0..size).map(|_| E::BaseField::random(&mut rng)).collect_vec())
                .collect_vec(),
        }];

        let real_challenges = vec![E::random(&mut rng), E::random(&mut rng)];

        let timer = Instant::now();

        let _ = AddInstruction::construct_graph_and_witness(
            &mut singer_builder.graph_builder,
            &mut singer_builder.chip_builder,
            &circuit_builder.insts_circuits[RV_INSTRUCTION as usize],
            vec![phase0],
            &real_challenges,
            1 << instance_num_vars,
            &SingerParams::default(),
        )
        .expect("gkr graph construction failed");

        let (graph, wit) = singer_builder.graph_builder.finalize_graph_and_witness();

        println!(
            "AddInstruction::construct_graph_and_witness, instance_num_vars = {}, time = {}",
            instance_num_vars,
            timer.elapsed().as_secs_f64()
        );

        let point = vec![E::random(&mut rng), E::random(&mut rng)];
        let target_evals = graph.target_evals(&wit, &point);

        let mut prover_transcript = &mut Transcript::new(b"Singer");

        let timer = Instant::now();
        let _ =
            GKRGraphProverState::prove(&graph, &wit, &target_evals, &mut prover_transcript, 1).expect("prove failed");
        println!(
            "AddInstruction::prove, instance_num_vars = {}, time
       = {}",
            instance_num_vars,
            timer.elapsed().as_secs_f64()
        );
    }

    #[test]
    #[cfg(not(debug_assertions))]
    fn bench_add_instruction() {
        bench_add_instruction_helper::<GoldilocksExt2>(10);
    }
}
