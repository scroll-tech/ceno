use goldilocks::Goldilocks;
use transcript::Transcript;
use zkvm::{
    constants::OpcodeType,
    singer_basic::{SingerBasic, SingerBasicCircuit},
    ZKVM,
};

fn main() {
    // PUSH 1 POP
    let bytecode = [0x60, 0x01, 0x50];
    let zkvm_circuit: SingerBasicCircuit<Goldilocks> =
        SingerBasic::construct_circuits(&[OpcodeType::PUSH1, OpcodeType::POP]);
    let (public_io, witness) = SingerBasic::witness_generation(&zkvm_circuit, &bytecode, &[])
        .expect("witness generation failed");

    let mut prover_transcript = Transcript::new(b"zkvm");
    let zkvm_proof = SingerBasic::prove(&zkvm_circuit, &witness, &mut prover_transcript);

    let mut verifier_transcript = Transcript::new(b"zkvm");
    SingerBasic::verify(
        &zkvm_circuit,
        &public_io,
        &zkvm_proof,
        &mut verifier_transcript,
    )
    .expect("verification failed");
}
