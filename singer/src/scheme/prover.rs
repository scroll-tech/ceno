use std::{collections::HashMap, mem};

use gkr::utils::MultilinearExtensionFromVectors;
use gkr_graph::structs::{CircuitGraphAuxInfo, NodeOutputType, PredType};
use goldilocks::SmallField;
use mpcs::{poly::multilinear::MultilinearPolynomial, Basefold, BasefoldCommitmentWithData, BasefoldDefaultParams, PolynomialCommitmentScheme};
use serde::{de::DeserializeOwned, Serialize};
use transcript::Transcript;
use itertools::{izip, Itertools};

use crate::{
    error::ZKVMError, SingerCircuit, SingerWiresOutID, SingerWiresOutValues, SingerWitness,
};

use super::{GKRGraphProverState, SingerProof};

type PCS<F> = Basefold::<F, BasefoldDefaultParams>;

pub fn prove<F: SmallField + DeserializeOwned>(
    pcs_param: &<PCS<F> as PolynomialCommitmentScheme<F, F>>::ProverParam,
    vm_circuit: &SingerCircuit<F>,
    vm_witness: &SingerWitness<F::BaseField>,
    vm_out_id: &SingerWiresOutID,
    transcript: &mut Transcript<F>,
) -> Result<(SingerProof<F>, CircuitGraphAuxInfo), ZKVMError> 
where
    F::BaseField: Serialize + DeserializeOwned,
    <F as SmallField>::BaseField: Into<F>
{
    // Prepare the commitments (with the corresponding data, i.e., the Merkle leaves and Merkle trees).
    // This array is indexed first by the node indices, then by the wire in indices for each node.
    let mut commitments_with_data = Vec::<Vec::<BasefoldCommitmentWithData::<F>>>::new();
    for (node, witness) in izip!(vm_circuit.0.nodes(), &vm_witness.0.node_witnesses) {
        let mut commitments_with_data_for_node = Vec::<BasefoldCommitmentWithData::<F>>::new();
        for (wire_id, pred) in node.preds().iter().enumerate() {
            if matches!(pred, PredType::Source) {
                // If this is a source wire in, i.e., a wire that is not copied from another node, but indeed an input
                // to this GKR circuit graph, then commit to this wire in.
                let mle = witness.witness_in_ref()[wire_id as usize]
                    .instances
                    .as_slice()
                    .original_mle();
                
                let commitment_with_data = PCS::<F>::commit(pcs_param, &MultilinearPolynomial::new(mle.evaluations.clone()))?;
                commitments_with_data_for_node.push(commitment_with_data);
            } else {
                // Otherwise, just store an empty commitment.
                commitments_with_data_for_node.push(BasefoldCommitmentWithData::default());
            }
        }
        commitments_with_data.push(commitments_with_data_for_node);
    }
    // With all the commitments ready, we can now write them to the transcript.
    for (node_id, wire_in_id) in vm_circuit.0.sources() {
        // The commitment of Basefold is just the root of the Merkle tree. The root is of type Digest<F>, which
        // is defined as an array of F::BaseField.
        let cm = commitments_with_data[node_id][wire_in_id as usize].get_root_ref();
        for element in cm.0 {
            // Note that this is only efficient when F is itself the base field.
            // When F is the extension field, the basefield elements should be packed before written to the transcript.
            transcript.append_field_element(&element.into());
        }
    }
    let point = (0..2 * F::DEGREE)
        .map(|_| {
            transcript
                .get_and_append_challenge(b"output point")
                .elements
        })
        .collect_vec();

    let singer_out_evals = {
        let target_wits = |node_out_ids: &[NodeOutputType]| {
            node_out_ids
                .iter()
                .map(|node| {
                    match node {
                        NodeOutputType::OutputLayer(node_id) => vm_witness.0.node_witnesses
                            [*node_id as usize]
                            .output_layer_witness_ref()
                            .instances
                            .iter()
                            .cloned()
                            .flatten(),
                        NodeOutputType::WireOut(node_id, wit_id) => vm_witness.0.node_witnesses
                            [*node_id as usize]
                            .witness_out_ref()[*wit_id as usize]
                            .instances
                            .iter()
                            .cloned()
                            .flatten(),
                    }
                    .collect_vec()
                })
                .collect_vec()
        };
        let ram_load = target_wits(&vm_out_id.ram_load);
        let ram_store = target_wits(&vm_out_id.ram_store);
        let rom_input = target_wits(&vm_out_id.rom_input);
        let rom_table = target_wits(&vm_out_id.rom_table);
        SingerWiresOutValues {
            ram_load,
            ram_store,
            rom_input,
            rom_table,
            public_output_size: vm_out_id
                .public_output_size
                .map(|node| mem::take(&mut target_wits(&[node])[0])),
        }
    };

    let aux_info = CircuitGraphAuxInfo {
        instance_num_vars: vm_witness
            .0
            .node_witnesses
            .iter()
            .map(|witness| witness.instance_num_vars())
            .collect(),
    };

    let target_evals = vm_circuit.0.target_evals(&vm_witness.0, &point);
    let (gkr_phase_proof, input_claims) =
        GKRGraphProverState::prove(&vm_circuit.0, &vm_witness.0, &target_evals, transcript)?;
    Ok((
        SingerProof {
            gkr_phase_proof,
            singer_out_evals,
        },
        aux_info,
    ))
}
