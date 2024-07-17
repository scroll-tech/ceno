use core::ops::Range;
use ff::Field;
use ff_ext::ExtensionField;
use gkr::structs::CircuitWitness;
use simple_frontend::structs::CellId;
use singer_utils::uint::UInt;
use std::collections::BTreeMap;

use crate::instructions::InstCircuit;

pub(crate) trait UIntParams {
    const BITS: usize;
    const CELL_BIT_WIDTH: usize;
}

impl<const M: usize, const C: usize> UIntParams for UInt<M, C> {
    const BITS: usize = M;
    const CELL_BIT_WIDTH: usize = C;
}

pub(crate) fn get_uint_params<T: UIntParams>() -> (usize, usize) {
    (T::BITS, T::CELL_BIT_WIDTH)
}

pub(crate) fn test_opcode_circuit_v2<Ext: ExtensionField>(
    inst_circuit: &InstCircuit<Ext>,
    phase0_idx_map: &BTreeMap<&'static str, Range<CellId>>,
    phase0_witness_size: usize,
    phase0_values_map: &BTreeMap<&'static str, Vec<Ext::BaseField>>,
    circuit_witness_challenges: Vec<Ext>,
) -> CircuitWitness<<Ext as ExtensionField>::BaseField> {
    // configure circuit
    let circuit = inst_circuit.circuit.as_ref();

    #[cfg(feature = "test-dbg")]
    println!("{:?}", circuit);

    // get indexes for circuit inputs and wire_in
    // only phase0
    let inputs_idxes = &inst_circuit.layout.phases_wire_id;
    let phase0_input_idx = inputs_idxes[0];

    // assign witnesses to circuit
    let n_witness_in = circuit.n_witness_in;
    let mut witness_in = vec![vec![]; n_witness_in];
    witness_in[phase0_input_idx as usize] = vec![Ext::BaseField::ZERO; phase0_witness_size];

    for key in phase0_idx_map.keys() {
        let range = phase0_idx_map
            .get(key)
            .unwrap()
            .clone()
            .collect::<Vec<CellId>>();
        let values = phase0_values_map
            .get(key)
            .expect(&("unknown key ".to_owned() + key));
        for (value_idx, cell_idx) in range.into_iter().enumerate() {
            if value_idx < values.len() {
                witness_in[phase0_input_idx as usize][cell_idx] = values[value_idx];
            }
        }
    }

    #[cfg(feature = "test-dbg")]
    println!("{:?}", witness_in);

    let circuit_witness = {
        let mut circuit_witness = CircuitWitness::new(&circuit, circuit_witness_challenges);
        circuit_witness.add_instance(&circuit, witness_in);
        circuit_witness
    };

    #[cfg(feature = "test-dbg")]
    println!("{:?}", circuit_witness);
    // dbg!(&circuit_witness);

    circuit_witness.check_correctness(&circuit);

    circuit_witness

    // let instance_num_vars = circuit_witness.instance_num_vars();
    // let (proof, output_num_vars, output_eval) = {
    // let mut prover_transcript = Transcript::<Goldilocks>::new(b"example");
    // let output_num_vars = instance_num_vars + circuit.first_layer_ref().num_vars();
    // let output_point = (0..output_num_vars)
    // .map(|_| {
    // prover_transcript
    // .get_and_append_challenge(b"output point")
    // .elements
    // })
    // .collect_vec();
    // let output_eval = circuit_witness
    // .layer_poly(0, circuit.first_layer_ref().num_vars())
    // .evaluate(&output_point);
    // (
    // IOPProverState::prove_parallel(
    // &circuit,
    // &circuit_witness,
    // &[(output_point, output_eval)],
    // &[],
    // &mut prover_transcript,
    // ),
    // output_num_vars,
    // output_eval,
    // )
    // };
    // let gkr_input_claims = {
    // let mut verifier_transcript = &mut Transcript::<Goldilocks>::new(b"example");
    // let output_point = (0..output_num_vars)
    // .map(|_| {
    // verifier_transcript
    // .get_and_append_challenge(b"output point")
    // .elements
    // })
    // .collect_vec();
    // IOPVerifierState::verify_parallel(
    // &circuit,
    // circuit_witness.challenges(),
    // &[(output_point, output_eval)],
    // &[],
    // &proof,
    // instance_num_vars,
    // &mut verifier_transcript,
    // )
    // .expect("verification failed")
    // };
    // let expected_values = circuit_witness
    // .witness_in_ref()
    // .iter()
    // .map(|witness| {
    // witness
    // .instances
    // .as_slice()
    // .mle(circuit.max_wit_in_num_vars.expect("REASON"), instance_num_vars)
    // .evaluate(&gkr_input_claims.point_and_evals)
    // })
    // .collect_vec();
    // for i in 0..gkr_input_claims.point_and_evals.len() {
    // assert_eq!(expected_values[i], gkr_input_claims.point_and_evals[i]);
    // }
    // println!("verification succeeded");
}

#[deprecated(note = "deprecated and use test_opcode_circuit_v2 instead")]
pub(crate) fn test_opcode_circuit<Ext: ExtensionField>(
    inst_circuit: &InstCircuit<Ext>,
    phase0_idx_map: &BTreeMap<&'static str, Range<CellId>>,
    phase0_witness_size: usize,
    phase0_values_map: &BTreeMap<String, Vec<Ext::BaseField>>,
    circuit_witness_challenges: Vec<Ext>,
) -> CircuitWitness<<Ext as ExtensionField>::BaseField> {
    let phase0_values_map = phase0_values_map
        .iter()
        .map(|(key, value)| (key.clone().leak() as &'static str, value.clone()))
        .collect::<BTreeMap<&'static str, Vec<Ext::BaseField>>>();
    test_opcode_circuit_v2(
        inst_circuit,
        phase0_idx_map,
        phase0_witness_size,
        &phase0_values_map,
        circuit_witness_challenges,
    )
}
