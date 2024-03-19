use std::mem;

use gkr_graph::structs::{CircuitGraphAuxInfo, NodeOutputType};
use goldilocks::SmallField;
use itertools::Itertools;
use transcript::Transcript;

use crate::{
    error::ZKVMError, SingerCircuit, SingerWiresOutID, SingerWiresOutValues, SingerWitness,
};

use super::{GKRGraphProverState, SingerProof};

pub fn prove<F: SmallField>(
    vm_circuit: &SingerCircuit<F>,
    vm_witness: &SingerWitness<F::BaseField>,
    vm_out_id: &SingerWiresOutID,
    transcript: &mut Transcript<F>,
) -> Result<(SingerProof<F>, CircuitGraphAuxInfo), ZKVMError> {
    // TODO: Add PCS.
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
    let gkr_phase_proof =
        GKRGraphProverState::prove(&vm_circuit.0, &vm_witness.0, &target_evals, transcript)?;
    Ok((
        SingerProof {
            gkr_phase_proof,
            singer_out_evals,
        },
        aux_info,
    ))
}
