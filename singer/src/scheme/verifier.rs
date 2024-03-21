use gkr::{structs::PointAndEval, utils::MultilinearExtensionFromVectors};
use gkr_graph::structs::TargetEvaluations;
use goldilocks::SmallField;
use itertools::{chain, Itertools};
use mpcs::{
    Basefold, BasefoldDefaultParams, Evaluation, NoninteractivePCS, PolynomialCommitmentScheme,
};
use serde::{de::DeserializeOwned, Serialize};
use transcript::Transcript;

use crate::{error::ZKVMError, SingerAuxInfo, SingerCircuit, SingerWiresOutValues};

use super::{GKRGraphVerifierState, SingerProof};
type PCS<F> = Basefold<F, BasefoldDefaultParams>;

pub fn verify<F: SmallField>(
    pcs_param: &<PCS<F> as PolynomialCommitmentScheme<F, F>>::VerifierParam,
    vm_circuit: &SingerCircuit<F>,
    vm_proof: SingerProof<F>,
    aux_info: &SingerAuxInfo,
    challenges: &[F],
    transcript: &mut Transcript<F>,
) -> Result<(), ZKVMError>
where
    F::BaseField: Serialize + DeserializeOwned,
    F: DeserializeOwned,
    <F as SmallField>::BaseField: Into<F>,
{
    // Put the commitments of the PCS proof to the transcript, just
    // as in prover.
    for commitment in vm_proof.pcs_commitments.iter() {
        // The commitment of Basefold is just the root of the Merkle tree. The root is of type Digest<F>, which
        // is defined as an array of F::BaseField.
        for element in commitment.root().0.iter() {
            // Note that this is only efficient when F is itself the base field.
            // When F is the extension field, the basefield elements should be packed before written to the transcript.
            transcript.append_field_element(&(*element).into());
        }
    }

    let point = (0..2 * F::DEGREE)
        .map(|_| {
            transcript
                .get_and_append_challenge(b"output point")
                .elements
        })
        .collect_vec();

    let SingerWiresOutValues {
        ram_load,
        ram_store,
        rom_input,
        rom_table,
        public_output_size,
    } = vm_proof.singer_out_evals;

    let ram_load_product: F = ram_load.iter().map(|x| F::from_limbs(&x)).product();
    let ram_store_product = ram_store.iter().map(|x| F::from_limbs(&x)).product();
    if ram_load_product != ram_store_product {
        return Err(ZKVMError::VerifyError);
    }

    let rom_input_sum = rom_input
        .iter()
        .map(|x| {
            let l = x.len();
            let (den, num) = x.split_at(l / 2);
            (F::from_limbs(den), F::from_limbs(num))
        })
        .fold((F::ONE, F::ZERO), |acc, x| {
            (acc.0 * x.0, acc.0 * x.1 + acc.1 * x.0)
        });
    let rom_table_sum = rom_table
        .iter()
        .map(|x| {
            let l = x.len();
            let (den, num) = x.split_at(l / 2);
            (F::from_limbs(den), F::from_limbs(num))
        })
        .fold((F::ONE, F::ZERO), |acc, x| {
            (acc.0 * x.0, acc.0 * x.1 + acc.1 * x.0)
        });
    if rom_input_sum.0 * rom_table_sum.1 != rom_input_sum.1 * rom_table_sum.0 {
        return Err(ZKVMError::VerifyError);
    }

    let mut target_evals = TargetEvaluations(
        chain![ram_load, ram_store, rom_input, rom_table,]
            .map(|x| {
                let f = vec![x.to_vec()].as_slice().original_mle();
                PointAndEval::new(
                    point[..f.num_vars].to_vec(),
                    f.evaluate(&point[..f.num_vars]),
                )
            })
            .collect_vec(),
    );

    if let Some(output) = public_output_size {
        let f = vec![output.to_vec()].as_slice().original_mle();
        target_evals.0.push(PointAndEval::new(
            point[..f.num_vars].to_vec(),
            f.evaluate(&point[..f.num_vars]),
        ));
        assert_eq!(
            output[0],
            F::BaseField::from(aux_info.program_output_len as u64)
        )
    }

    let pcs_point_evals = GKRGraphVerifierState::verify(
        &vm_circuit.0,
        &challenges,
        &target_evals,
        vm_proof.gkr_phase_proof,
        &aux_info.graph_aux_info,
        transcript,
    )?;
    // The pcs point evals returned from the GKR graph verifier
    // is a two-dimensional vector indexed by the node id and the
    // wire id. First, rearrange it into a one-dimensional vector
    // ordered by the `sources` of the circuit.
    let mut points = vec![];
    let mut evals = vec![];
    for (node_id, wire_in_id) in vm_circuit.0.sources() {
        points.push(pcs_point_evals[node_id][wire_in_id as usize].point.clone());
        evals.push(Evaluation::new(
            points.len() - 1, // The index of the current polynomial (which is equal to the index of the current point).
            points.len() - 1, // The index of the current point.
            pcs_point_evals[node_id][wire_in_id as usize].eval,
        ));
    }
    PCS::<F>::ni_batch_verify(
        &pcs_param,
        &vm_proof.pcs_commitments,
        &points,
        &evals,
        &vm_proof.pcs_proof,
    )?;

    Ok(())
}
