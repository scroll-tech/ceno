use ark_std::rand::SeedableRng;
use goldilocks::Goldilocks;
use itertools::Itertools;
use mpcs::{
    pcs_setup, pcs_trim, Basefold, BasefoldDefault, BasefoldDefaultParams, BasefoldParams,
    PolynomialCommitmentScheme,
};
use rand_chacha::ChaCha8Rng;
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

    let (pp, vp) = {
        let rng = ChaCha8Rng::from_seed([0u8; 32]);
        let poly_size = 1 << 15; // Temporarily set to 15. Modify it to appropriate size later.
        let param: BasefoldParams<Goldilocks, ChaCha8Rng> =
            pcs_setup::<Goldilocks, Goldilocks, BasefoldDefault<Goldilocks>>(poly_size, &rng)
                .unwrap();
        pcs_trim::<Goldilocks, Goldilocks, BasefoldDefault<Goldilocks>>(&param).unwrap()
    };

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

        let (proof, graph_aux_info) = prove(
            &pp,
            &circuit,
            &witness,
            &wires_out_id,
            &mut prover_transcript,
        )
        .expect("prove failed");
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
        &vp,
        &circuit,
        proof,
        &singer_aux_info,
        &real_challenges,
        &mut verifier_transcript,
    )
    .expect("verify failed");
}
