use gkr_graph::structs::CircuitGraphBuilder;
use goldilocks::GoldilocksExt2;
use singer_pro::{
    basic_block::SingerBasicBlockBuilder, chips::SingerChipBuilder, component::ChipChallenges,
    instructions::SingerInstCircuitBuilder, SingerGraphBuilder, SingerWitness,
};

fn main() {
    let challenges = ChipChallenges::default();
    let circuit_builder = SingerInstCircuitBuilder::<GoldilocksExt2>::new(challenges)
        .expect("failed to create circuit builder");
    let chip_builder = SingerChipBuilder::new(challenges);

    let bytecode = vec![vec![0x60, 0x01, 0x50]];
    let bb_builder = SingerBasicBlockBuilder::new(circuit_builder, bytecode, challenges)
        .expect("failed to create basic block builder");
    let singer_builder = SingerGraphBuilder::new(bb_builder, chip_builder, challenges)
        .expect("failed to create graph builder");

    // 1. Commit witness.

    // 2. Construct circuit graph.
    // let (circuit, witness, wires_out_id) = singer_builder.construct(
    //     &circuit_builder,
    //     singer_wires_in,
    //     program_input,
    //     real_challenges,
    // );

    // 3. Prove.

    // 4. Verify.
}
