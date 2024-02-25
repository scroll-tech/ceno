use goldilocks::Goldilocks;
use itertools::Itertools;
use singer::{
    instructions::SingerCircuitBuilder,
    scheme::{prover::prove, verifier::verify},
    SingerAuxInfo, SingerGraphBuilder, SingerParams, SingerWiresIn,
};
use singer_utils::structs::ChipChallenges;
use transcript::Transcript;

fn main() {
    let chip_challenges = ChipChallenges::default();
    let circuit_builder =
        SingerCircuitBuilder::<Goldilocks>::new(chip_challenges).expect("circuit builder failed");
    let singer_builder = SingerGraphBuilder::<Goldilocks>::new();

    let bytecode = [0x60 as u8, 0x01, 0x50];

    let mut prover_transcript = Transcript::new(b"Singer");

    // TODO: Generate the following items.
    let singer_wires_in = SingerWiresIn::default();
    let real_challenges = vec![];
    let singer_params = SingerParams::default();

    let (proof, singer_aux_info) = {
        let real_n_instances = singer_wires_in
            .instructions
            .iter()
            .map(|x| (x.opcode, x.real_n_instances))
            .collect_vec();
        let (circuit, witness, wires_out_id) = singer_builder
            .construct_graph_and_witness(
                &circuit_builder,
                singer_wires_in,
                &bytecode,
                &[],
                &real_challenges,
                &singer_params,
            )
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
    let mut verifier_transcript = Transcript::new(b"Singer");
    let singer_builder = SingerGraphBuilder::<Goldilocks>::new();
    let circuit = singer_builder
        .construct_graph(&circuit_builder, &singer_aux_info)
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
