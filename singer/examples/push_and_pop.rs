use goldilocks::Goldilocks;
use singer::{
    chips::SingerChipBuilder, instructions::ChipChallenges, SingerCircuitBuilder,
    SingerGraphBuilder,
};

fn main() {
    let chip_challenges = ChipChallenges::default();
    let circuit_builder = SingerCircuitBuilder::<Goldilocks>::new(chip_challenges);
    let singer_builder = SingerGraphBuilder::<Goldilocks>::new();

    let bytecode = [0x60, 0x01, 0x50];

    // 1. Commit witness.

    // 2. Construct circuit graph.

    // let (circuit, witness, wires_out_id) = singer_builder.construct(
    //     &circuit_builder,
    //     singer_wires_in,
    //     bytecode,
    //     &[],
    //     real_challenges,
    //     params,
    // );

    // 3. Prove.

    // 4. Verify.
}
