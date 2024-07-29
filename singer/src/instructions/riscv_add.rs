use std::marker::PhantomData;

use ff_ext::ExtensionField;

use singer_utils::{
    self,
    chip_handler_v2::{GlobalStateRegisterMachineChipOperations, RegisterChipOperations},
    constants::OpcodeType,
    structs::{PCUIntV2, TSUIntV2, UInt64V2},
    structs_v2::CircuitBuilderV2,
    util_v2::{self, ToExpr, WitIn},
};

use util_v2::{InstructionV2, ZKVMV2Error};

pub struct AddInstructionV2;

// impl<E: ExtensionField> InstructionGraph<E> for AddInstruction {
//     type InstType = Self;
// }

pub struct InstructionConfig<E: ExtensionField> {
    pub pc: PCUIntV2,
    pub memory_ts: TSUIntV2,
    pub clk: WitIn,
    phantom: PhantomData<E>,
    prev_rd_memory_value: singer_utils::unit_v2::UIntV2<64, 32>,
    addend_0: singer_utils::unit_v2::UIntV2<64, 32>,
    addend_1: singer_utils::unit_v2::UIntV2<64, 32>,
    outcome: singer_utils::unit_v2::UIntV2<64, 32>,
    rs1_id: WitIn,
    rs2_id: WitIn,
    rd_id: WitIn,
    prev_rs1_memory_ts: singer_utils::unit_v2::UIntV2<48, 48>,
    prev_rs2_memory_ts: singer_utils::unit_v2::UIntV2<48, 48>,
    prev_rd_memory_ts: singer_utils::unit_v2::UIntV2<48, 48>,
}

impl<E: ExtensionField> InstructionV2<E> for AddInstructionV2 {
    const OPCODE: OpcodeType = OpcodeType::ADD;
    const NAME: &'static str = "ADD";
    type InstructionConfig = InstructionConfig<E>;
    fn construct_circuit(
        circuit_builder: &mut CircuitBuilderV2<E>,
    ) -> Result<InstructionConfig<E>, ZKVMV2Error> {
        let pc = PCUIntV2::new(circuit_builder);
        let memory_ts = TSUIntV2::new(circuit_builder);
        let clk = circuit_builder.create_witin();

        // state in
        // all of them should implement expr
        circuit_builder.state_in(&pc, &memory_ts, clk.expr())?;

        let next_pc = pc.add_const(circuit_builder, 1.into())?;
        let next_memory_ts = memory_ts.add_const(circuit_builder, 1.into())?;

        circuit_builder.state_out(&next_pc, &next_memory_ts, clk.expr() + 1.into())?;

        // Execution result = addend0 + addend1, with carry.
        let prev_rd_memory_value = UInt64V2::new(circuit_builder);
        let addend_0 = UInt64V2::new(circuit_builder);
        let addend_1 = UInt64V2::new(circuit_builder);
        let outcome = UInt64V2::new(circuit_builder);

        let computed_outcome = addend_0.add(circuit_builder, &addend_1)?;
        outcome.eq(circuit_builder, &computed_outcome)?;

        let rs1_id = circuit_builder.create_witin();
        let rs2_id = circuit_builder.create_witin();
        let rd_id = circuit_builder.create_witin();
        let prev_rs1_memory_ts = TSUIntV2::new(circuit_builder);
        let prev_rs2_memory_ts = TSUIntV2::new(circuit_builder);
        let prev_rd_memory_ts = TSUIntV2::new(circuit_builder);

        let is_lt_0 = prev_rs1_memory_ts.lt(circuit_builder, &memory_ts)?;
        let is_lt_1 = prev_rs2_memory_ts.lt(circuit_builder, &memory_ts)?;
        let is_lt_2 = prev_rd_memory_ts.lt(circuit_builder, &memory_ts)?;

        // less than = true
        circuit_builder.require_one(is_lt_0)?;
        circuit_builder.require_one(is_lt_1)?;
        circuit_builder.require_one(is_lt_2)?;

        circuit_builder.register_read(&rs1_id, &prev_rs1_memory_ts, &memory_ts, &addend_0)?;

        circuit_builder.register_read(&rs2_id, &prev_rs2_memory_ts, &memory_ts, &addend_1)?;

        circuit_builder.register_write(
            &rd_id,
            &prev_rd_memory_ts,
            &memory_ts,
            &prev_rd_memory_value,
            &computed_outcome,
        )?;

        Ok(InstructionConfig {
            pc,
            memory_ts,
            clk,
            prev_rd_memory_value,
            addend_0,
            addend_1,
            outcome,
            rs1_id,
            rs2_id,
            rd_id,
            prev_rs1_memory_ts,
            prev_rs2_memory_ts,
            prev_rd_memory_ts,
            phantom: PhantomData,
        })
    }
}

#[cfg(test)]
mod test {
    use ark_std::test_rng;
    use ff::Field;
    use ff_ext::ExtensionField;
    use goldilocks::{Goldilocks, GoldilocksExt2};
    use singer_utils::{structs_v2::CircuitBuilderV2, util_v2::InstructionV2};
    use transcript::Transcript;

    use crate::{
        instructions::{
            AddInstruction, ChipChallenges, Instruction, InstructionGraph, SingerCircuitBuilder,
        },
        scheme::GKRGraphProverState,
        test::{get_uint_params, test_opcode_circuit_v2},
        utils::u64vec,
        CircuitWiresIn, SingerGraphBuilder, SingerParams,
    };

    use super::AddInstructionV2;

    #[test]
    fn test_add_construct_circuit() {
        // The actual challenges used is:
        // challenges
        //  { ChallengeConst { challenge: 1, exp: i }: [Goldilocks(c^i)] }
        let c = GoldilocksExt2::from(6u64);

        let mut circuit_builder = CircuitBuilderV2::<GoldilocksExt2>::new();
        let _ = AddInstructionV2::construct_circuit(&mut circuit_builder);

        println!("circuit_builder {:?}", circuit_builder);
    }

    fn bench_add_instruction_helper<E: ExtensionField>(instance_num_vars: usize) {
        // let chip_challenges = ChipChallenges::default();
        // let circuit_builder =
        //     SingerCircuitBuilder::<E>::new(chip_challenges).expect("circuit builder failed");
        // let mut singer_builder = SingerGraphBuilder::<E>::new();

        // let mut rng = test_rng();
        // let size = AddInstruction::phase0_size();
        // let phase0: CircuitWiresIn<E> = vec![
        //     (0..(1 << instance_num_vars))
        //         .map(|_| {
        //             (0..size)
        //                 .map(|_| E::BaseField::random(&mut rng))
        //                 .collect_vec()
        //         })
        //         .collect_vec()
        //         .into(),
        // ];

        // let real_challenges = vec![E::random(&mut rng), E::random(&mut rng)];

        // let timer = Instant::now();

        // let _ = AddInstruction::construct_graph_and_witness(
        //     &mut singer_builder.graph_builder,
        //     &mut singer_builder.chip_builder,
        //     &circuit_builder.insts_circuits[<AddInstruction as Instruction<E>>::OPCODE as usize],
        //     vec![phase0],
        //     &real_challenges,
        //     1 << instance_num_vars,
        //     &SingerParams::default(),
        // )
        // .expect("gkr graph construction failed");

        // let (graph, wit) = singer_builder.graph_builder.finalize_graph_and_witness();

        // println!(
        //     "AddInstruction::construct_graph_and_witness, instance_num_vars = {}, time = {}",
        //     instance_num_vars,
        //     timer.elapsed().as_secs_f64()
        // );

        // let point = vec![E::random(&mut rng), E::random(&mut rng)];
        // let target_evals = graph.target_evals(&wit, &point);

        // let mut prover_transcript = &mut Transcript::new(b"Singer");

        // let timer = Instant::now();
        // let _ = GKRGraphProverState::prove(&graph, &wit, &target_evals, &mut prover_transcript, 1)
        //     .expect("prove failed");
        // println!(
        //     "AddInstruction::prove, instance_num_vars = {}, time = {}",
        //     instance_num_vars,
        //     timer.elapsed().as_secs_f64()
        // );
    }

    #[test]
    fn bench_add_instruction() {
        bench_add_instruction_helper::<GoldilocksExt2>(10);
    }
}
