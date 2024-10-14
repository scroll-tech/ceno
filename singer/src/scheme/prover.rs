use ff_ext::ExtensionField;
use gkr_graph::structs::{CircuitGraphAuxInfo, NodeOutputType};
use itertools::Itertools;
use multilinear_extensions::virtual_poly_v2::ArcMultilinearExtension;
use transcript::Transcript;

use crate::{
    error::ZKVMError, SingerCircuit, SingerWiresOutID, SingerWiresOutValues, SingerWitness,
};

use super::{GKRGraphProverState, SingerProof};

pub fn prove<'a, E: ExtensionField>(
    vm_circuit: &SingerCircuit<E>,
    vm_witness: &SingerWitness<'a, E>,
    vm_out_id: &SingerWiresOutID,
    transcript: &mut Transcript<E>,
) -> Result<
    (
        SingerProof<E>,
        CircuitGraphAuxInfo,
        SingerWiresOutValues<'a, E>,
    ),
    ZKVMError,
> {
    // TODO: Add PCS.
    let point = (0..2 * <E as ExtensionField>::DEGREE)
        .map(|_| {
            transcript
                .get_and_append_challenge(b"output point")
                .elements
        })
        .collect_vec();

    let singer_out_evals = {
        let target_wits = |node_out_ids: &[NodeOutputType]| -> Vec<ArcMultilinearExtension<E>> {
            node_out_ids
                .iter()
                .map(|node| match node {
                    NodeOutputType::OutputLayer(node_id) => vm_witness.0.node_witnesses[*node_id]
                        .output_layer_witness_ref()
                        .clone(),
                    NodeOutputType::WireOut(node_id, wit_id) => {
                        vm_witness.0.node_witnesses[*node_id].witness_out_ref()[*wit_id as usize]
                            .clone()
                    }
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
                .map(|node| target_wits(&[node])[0].clone()),
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
        GKRGraphProverState::prove(&vm_circuit.0, &vm_witness.0, &target_evals, transcript, 1)?;
    Ok((SingerProof { gkr_phase_proof }, aux_info, singer_out_evals))
}
