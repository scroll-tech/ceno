use goldilocks::Goldilocks;
use itertools::Itertools;
use singer_pro::{
    instructions::SingerInstCircuitBuilder,
    scheme::{prover::prove, verifier::verify},
    SingerAuxInfo, SingerGraphBuilder, SingerParams, SingerWiresIn,
};
use singer_utils::structs::ChipChallenges;
use transcript::Transcript;

fn main() {
    let chip_challenges = ChipChallenges::default();
    let circuit_builder = SingerInstCircuitBuilder::<Goldilocks>::new(chip_challenges)
        .expect("circuit builder failed");

    let bytecode = vec![vec![0x60 as u8, 0x01, 0x50]];
    let singer_builder =
        SingerGraphBuilder::<Goldilocks>::new(circuit_builder.clone(), &bytecode, chip_challenges)
            .expect("graph builder failed");

    let mut prover_transcript = Transcript::new(b"Singer pro");

    // TODO: Generate the following items.
    let singer_wires_in = SingerWiresIn::default();
    let real_challenges = vec![];
    let singer_params = SingerParams::default();

    let (proof, singer_aux_info) = {
        let real_n_instances = singer_wires_in
            .basic_blocks
            .iter()
            .map(|x| x.real_n_instance)
            .collect_vec();
        let (circuit, witness, wires_out_id) = singer_builder
            .construct_graph_and_witness(singer_wires_in, &[], &real_challenges, &singer_params)
            .expect("construct failed");

        let (proof, graph_aux_info) =
            prove(&circuit, &witness, &wires_out_id, &mut prover_transcript).expect("prove failed");
        let aux_info = SingerAuxInfo {
            graph_aux_info,
            real_n_instances,
            singer_params,
            bytecode_len: bytecode.len(),
            ..Default::default()
        };
        (proof, aux_info)
    };

    // 4. Verify.
    let mut verifier_transcript = Transcript::new(b"Singer pro");
    let singer_builder =
        SingerGraphBuilder::<Goldilocks>::new(circuit_builder, &bytecode, chip_challenges)
            .expect("graph builder failed");
    let circuit = singer_builder
        .construct_graph(&singer_aux_info)
        .expect("construct failed");
    verify(
        &circuit,
        proof,
        &singer_aux_info,
        &real_challenges,
        &mut verifier_transcript,
    )
    .expect("verify failed");
}
