use ff::Field;
use ff_ext::ExtensionField;
use gkr::structs::Circuit;
use paste::paste;
use simple_frontend::structs::{CircuitBuilder, MixedCell};
use singer_utils::{
    chip_handler::{
        BytecodeChipOperations, GlobalStateChipOperations, OAMOperations, ROMOperations,
        RangeChipOperations, RegisterChipOperations, StackChipOperations,
    },
    constants::OpcodeType,
    register_witness,
    structs::{PCUInt, RAMHandler, ROMHandler, RegisterUInt, StackUInt, TSUInt, UInt64},
    uint::{UIntAddSub, UIntCmp},
};
use std::sync::Arc;

use crate::error::ZKVMError;

use super::{ChipChallenges, InstCircuit, InstCircuitLayout, Instruction, InstructionGraph};

pub struct RVAddInstruction;

impl<E: ExtensionField> InstructionGraph<E> for RVAddInstruction {
    type InstType = Self;
}

register_witness!(
    RVAddInstruction,
    phase0 {
        pc => PCUInt::N_OPRAND_CELLS,
        register_ts => TSUInt::N_OPRAND_CELLS,
        memory_ts => TSUInt::N_OPRAND_CELLS,
        clk => 1,

        rs1 => RegisterUInt::N_OPRAND_CELLS,
        rs2 => RegisterUInt::N_OPRAND_CELLS,
        rd => RegisterUInt::N_OPRAND_CELLS,

        pc_add => UIntAddSub::<PCUInt>::N_NO_OVERFLOW_WITNESS_UNSAFE_CELLS,

        // instruction operation
        addend_0 => UInt64::N_OPRAND_CELLS,
        addend_1 => UInt64::N_OPRAND_CELLS,
        instruction_add => UIntAddSub::<UInt64>::N_WITNESS_CELLS,

        // register timestamps and comparison gadgets
        rs1_ts => TSUInt::N_OPRAND_CELLS,
        rs2_ts => TSUInt::N_OPRAND_CELLS,
        rs1_ts_lt => UIntCmp::<TSUInt>::N_WITNESS_CELLS,
        rs2_ts_lt => UIntCmp::<TSUInt>::N_WITNESS_CELLS
    }
);

impl<E: ExtensionField> Instruction<E> for RVAddInstruction {
    const OPCODE: OpcodeType = OpcodeType::RV_ADD;
    const NAME: &'static str = "RV_ADD";
    fn construct_circuit(challenges: ChipChallenges) -> Result<InstCircuit<E>, ZKVMError> {
        let mut circuit_builder = CircuitBuilder::new();
        let (phase0_wire_id, phase0) = circuit_builder.create_witness_in(Self::phase0_size());
        let mut ram_handler = RAMHandler::new(&challenges);
        let mut rom_handler = ROMHandler::new(&challenges);

        let pc = PCUInt::try_from(&phase0[Self::phase0_pc()])?;
        let memory_ts = &phase0[Self::phase0_memory_ts()];
        let register_ts = &phase0[Self::phase0_register_ts()];
        let clk = phase0[Self::phase0_clk().start];
        let clk_expr = MixedCell::Cell(clk);
        let zero_cell_ids = [0];
        let stack_top_expr = MixedCell::Cell(0);

        // Bytecode check for (pc, add)
        rom_handler.bytecode_with_pc_opcode(
            &mut circuit_builder,
            pc.values(),
            <Self as Instruction<E>>::OPCODE,
        );

        // State update
        ram_handler.state_in(
            &mut circuit_builder,
            pc.values(),
            &zero_cell_ids, // we don't have stack info here
            &memory_ts,
            0,
            clk,
        );

        let next_pc =
            ROMHandler::add_pc_const(&mut circuit_builder, &pc, 1, &phase0[Self::phase0_pc_add()])?;

        ram_handler.state_out(
            &mut circuit_builder,
            next_pc.values(),
            &zero_cell_ids,
            &memory_ts,
            stack_top_expr,
            clk_expr.add(E::BaseField::ONE),
        );

        // Register timestamp range check
        let rs1_ts = (&phase0[Self::phase0_rs1_ts()]).try_into()?;
        let rs2_ts = (&phase0[Self::phase0_rs2_ts()]).try_into()?;
        UIntCmp::<TSUInt>::assert_lt(
            &mut circuit_builder,
            &mut rom_handler,
            &rs1_ts,
            &register_ts.try_into()?,
            &phase0[Self::phase0_rs1_ts_lt()],
        )?;
        UIntCmp::<TSUInt>::assert_lt(
            &mut circuit_builder,
            &mut rom_handler,
            &rs2_ts,
            &register_ts.try_into()?,
            &phase0[Self::phase0_rs2_ts_lt()],
        )?;
        if cfg!(feature = "dbg-opcode") {
            println!(
                "addInstCircuit::phase0_instruction_add: {:?}",
                Self::phase0_instruction_add()
            );
        }

        // Execution result = addend0 + addend1, with carry.
        let addend_0 = (&phase0[Self::phase0_addend_0()]).try_into()?;
        let addend_1 = (&phase0[Self::phase0_addend_1()]).try_into()?;
        let result = UIntAddSub::<UInt64>::add(
            &mut circuit_builder,
            &mut rom_handler,
            &addend_0,
            &addend_1,
            &phase0[Self::phase0_instruction_add()],
        )?;

        // Read/Write from registers
        let rs1 = &phase0[Self::phase0_rs1()];
        let rs2 = &phase0[Self::phase0_rs2()];
        let rd = &phase0[Self::phase0_rd()];
        ram_handler.register_read(
            &mut circuit_builder,
            rs1,
            rs1_ts.values(),
            addend_0.values(),
        );
        ram_handler.register_read(
            &mut circuit_builder,
            rs2,
            rs2_ts.values(),
            addend_1.values(),
        );
        ram_handler.register_store(&mut circuit_builder, rd, register_ts, result.values());

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
    use core::ops::Range;
    use ff::Field;
    use ff_ext::ExtensionField;
    use gkr::structs::LayerWitness;
    use goldilocks::{Goldilocks, GoldilocksExt2};
    use itertools::Itertools;
    use simple_frontend::structs::CellId;
    use singer_utils::{
        constants::RANGE_CHIP_BIT_WIDTH,
        structs::{StackUInt, TSUInt},
    };
    use std::{collections::BTreeMap, time::Instant};
    use transcript::Transcript;

    use crate::{
        instructions::{
            ChipChallenges, Instruction, InstructionGraph, RVAddInstruction, SingerCircuitBuilder,
        },
        scheme::GKRGraphProverState,
        test::{get_uint_params, test_opcode_circuit, u2vec},
        CircuitWiresIn, SingerGraphBuilder, SingerParams,
    };

    impl RVAddInstruction {
        #[inline]
        fn phase0_idxes_map() -> BTreeMap<String, Range<CellId>> {
            let mut map = BTreeMap::new();
            map.insert("phase0_pc".to_string(), Self::phase0_pc());
            map.insert("phase0_register_ts".to_string(), Self::phase0_register_ts());
            map.insert("phase0_memory_ts".to_string(), Self::phase0_memory_ts());
            map.insert("phase0_clk".to_string(), Self::phase0_clk());

            map.insert("phase0_rs1".to_string(), Self::phase0_rs1());
            map.insert("phase0_rs2".to_string(), Self::phase0_rs2());
            map.insert("phase0_rd".to_string(), Self::phase0_rd());

            map.insert("phase0_pc_add".to_string(), Self::phase0_pc_add());
            map.insert("phase0_addend_0".to_string(), Self::phase0_addend_0());
            map.insert("phase0_addend_1".to_string(), Self::phase0_addend_1());
            map.insert(
                "phase0_instruction_add".to_string(),
                Self::phase0_instruction_add(),
            );

            map.insert("phase0_rs1_ts".to_string(), Self::phase0_rs1_ts());
            map.insert("phase0_rs2_ts".to_string(), Self::phase0_rs2_ts());
            map.insert("phase0_rs1_ts_lt".to_string(), Self::phase0_rs1_ts_lt());
            map.insert("phase0_rs2_ts_lt".to_string(), Self::phase0_rs2_ts_lt());

            map
        }
    }

    #[test]
    fn test_add_construct_circuit() {
        let challenges = ChipChallenges::default();

        let phase0_idx_map = RVAddInstruction::phase0_idxes_map();
        let phase0_witness_size = RVAddInstruction::phase0_size();

        if cfg!(feature = "test-dbg") {
            println!("ADD: {:?}", &phase0_idx_map);
            println!("ADD witness_size: {:?}", phase0_witness_size);
        }

        // initialize general test inputs associated with push1
        let inst_circuit = RVAddInstruction::construct_circuit(challenges).unwrap();

        if cfg!(feature = "test-dbg") {
            println!("{:?}", inst_circuit);
        }

        let mut phase0_values_map = BTreeMap::<String, Vec<Goldilocks>>::new();
        phase0_values_map.insert("phase0_pc".to_string(), vec![Goldilocks::from(1u64)]);
        phase0_values_map.insert(
            "phase0_register_ts".to_string(),
            vec![Goldilocks::from(3u64)],
        );
        phase0_values_map.insert("phase0_memory_ts".to_string(), vec![Goldilocks::from(1u64)]);
        phase0_values_map.insert("phase0_clk".to_string(), vec![Goldilocks::from(1u64)]);
        phase0_values_map.insert(
            "phase0_pc_add".to_string(),
            vec![], // carry is 0, may test carry using larger values in PCUInt
        );

        // register id assigned
        phase0_values_map.insert("phase0_rs1".to_string(), vec![Goldilocks::from(1u64)]);
        phase0_values_map.insert("phase0_rs2".to_string(), vec![Goldilocks::from(2u64)]);
        phase0_values_map.insert("phase0_rd".to_string(), vec![Goldilocks::from(3u64)]);

        let m: u64 = (1 << get_uint_params::<StackUInt>().1) - 1;
        phase0_values_map.insert("phase0_addend_0".to_string(), vec![Goldilocks::from(m)]);
        phase0_values_map.insert("phase0_addend_1".to_string(), vec![Goldilocks::from(1u64)]);
        let range_values = u2vec::<{ StackUInt::N_RANGE_CHECK_CELLS }, RANGE_CHIP_BIT_WIDTH>(m + 1);
        let mut wit_phase0_instruction_add: Vec<Goldilocks> = vec![];
        for i in 0..16 {
            wit_phase0_instruction_add.push(Goldilocks::from(range_values[i]))
        }
        wit_phase0_instruction_add.push(Goldilocks::from(1u64)); // carry is [1, 0, ...]
        phase0_values_map.insert(
            "phase0_instruction_add".to_string(),
            wit_phase0_instruction_add,
        );

        phase0_values_map.insert("phase0_rs1_ts".to_string(), vec![Goldilocks::from(2u64)]);
        let m: u64 = (1 << get_uint_params::<TSUInt>().1) - 1;
        let range_values = u2vec::<{ TSUInt::N_RANGE_CHECK_CELLS }, RANGE_CHIP_BIT_WIDTH>(m);
        phase0_values_map.insert(
            "phase0_rs1_ts_lt".to_string(),
            vec![
                Goldilocks::from(range_values[0]),
                Goldilocks::from(range_values[1]),
                Goldilocks::from(range_values[2]),
                Goldilocks::from(range_values[3]),
                Goldilocks::from(1u64), // borrow
            ],
        );
        phase0_values_map.insert("phase0_rs2_ts".to_string(), vec![Goldilocks::from(1u64)]);
        let m: u64 = (1 << get_uint_params::<TSUInt>().1) - 2;
        let range_values = u2vec::<{ TSUInt::N_RANGE_CHECK_CELLS }, RANGE_CHIP_BIT_WIDTH>(m);
        phase0_values_map.insert(
            "phase0_rs2_ts_lt".to_string(),
            vec![
                Goldilocks::from(range_values[0]),
                Goldilocks::from(range_values[1]),
                Goldilocks::from(range_values[2]),
                Goldilocks::from(range_values[3]),
                Goldilocks::from(1u64), // borrow
            ],
        );
        // The actual challenges used is:
        // challenges
        //  { ChallengeConst { challenge: 1, exp: i }: [Goldilocks(c^i)] }
        let c = GoldilocksExt2::from(6u64);
        let circuit_witness_challenges = vec![c; 3];

        let circuit_witness = test_opcode_circuit(
            &inst_circuit,
            &phase0_idx_map,
            phase0_witness_size,
            &phase0_values_map,
            circuit_witness_challenges,
        );
    }

    // fn bench_add_instruction_helper<E: ExtensionField>(instance_num_vars: usize) {
    //     let chip_challenges = ChipChallenges::default();
    //     let circuit_builder =
    //         SingerCircuitBuilder::<E>::new(chip_challenges).expect("circuit builder failed");
    //     let mut singer_builder = SingerGraphBuilder::<E>::new();

    //     let mut rng = test_rng();
    //     let size = RVAddInstruction::phase0_size();
    //     let phase0: CircuitWiresIn<E::BaseField> = vec![LayerWitness {
    //         instances: (0..(1 << instance_num_vars))
    //             .map(|_| {
    //                 (0..size)
    //                     .map(|_| E::BaseField::random(&mut rng))
    //                     .collect_vec()
    //             })
    //             .collect_vec(),
    //     }];

    //     let real_challenges = vec![E::random(&mut rng), E::random(&mut rng)];

    //     let timer = Instant::now();

    //     let _ = RVAddInstruction::construct_graph_and_witness(
    //         &mut singer_builder.graph_builder,
    //         &mut singer_builder.chip_builder,
    //         &circuit_builder.insts_circuits[<RVAddInstruction as InstructionRV<E>>::OPCODE as
    // usize],         vec![phase0],
    //         &real_challenges,
    //         1 << instance_num_vars,
    //         &SingerParams::default(),
    //     )
    //     .expect("gkr graph construction failed");

    //     let (graph, wit) = singer_builder.graph_builder.finalize_graph_and_witness();

    //     println!(
    //         "RVAddInstruction::construct_graph_and_witness, instance_num_vars = {}, time = {}",
    //         instance_num_vars,
    //         timer.elapsed().as_secs_f64()
    //     );

    //     let point = vec![E::random(&mut rng), E::random(&mut rng)];
    //     let target_evals = graph.target_evals(&wit, &point);

    //     let mut prover_transcript = &mut Transcript::new(b"Singer");

    //     let timer = Instant::now();
    //     let _ = GKRGraphProverState::prove(&graph, &wit, &target_evals, &mut prover_transcript,
    // 1) .expect("prove failed"); println!( "RVAddInstruction::prove, instance_num_vars = {}, time
    //    = {}", instance_num_vars, timer.elapsed().as_secs_f64() );
    // }

    // #[test]
    // fn bench_add_instruction() {
    //     bench_add_instruction_helper::<GoldilocksExt2>(10);
    // }
}
