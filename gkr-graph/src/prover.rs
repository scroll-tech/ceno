use gkr::{
    structs::{IOPProverPhase2Message, PointAndEval},
    utils::MultilinearExtensionFromVectors,
};
use goldilocks::SmallField;
use itertools::izip;
use std::mem;
use transcript::Transcript;

use crate::{
    error::GKRGraphError,
    structs::{
        CircuitGraph, CircuitGraphWitness, IOPProof, IOPProverState, NodeOutputType, PredType,
        TargetEvaluations,
    },
};

impl<F: SmallField> IOPProverState<F> {
    pub fn prove(
        circuit: &CircuitGraph<F>,
        circuit_witness: &CircuitGraphWitness<F::BaseField>,
        target_evals: &TargetEvaluations<F>,
        transcript: &mut Transcript<F>,
    ) -> Result<IOPProof<F>, GKRGraphError> {
        assert_eq!(target_evals.0.len(), circuit.targets.len());

        let mut output_evals = vec![vec![]; circuit.nodes.len()];
        let mut wires_out_evals = vec![vec![]; circuit.nodes.len()];
        izip!(&circuit.targets, &target_evals.0).for_each(|(target, eval)| match target {
            NodeOutputType::OutputLayer(id) => output_evals[*id].push(eval.clone()),
            NodeOutputType::WireOut(id, _) => wires_out_evals[*id].push(eval.clone()),
        });

        let gkr_proofs = izip!(
            0..circuit.nodes.len(),
            &circuit.nodes,
            &circuit_witness.node_witnesses
        )
        .rev()
        .map(|(id, node, witness)| {
            let proof = gkr::structs::IOPProverState::prove_parallel(
                &node.circuit,
                witness,
                &mem::take(&mut output_evals[id]),
                &mem::take(&mut wires_out_evals[id]),
                transcript,
            );

            let IOPProverPhase2Message {
                sumcheck_proofs,
                sumcheck_eval_values,
            } = &proof.sumcheck_proofs.last().unwrap().1;
            izip!(sumcheck_proofs, sumcheck_eval_values).for_each(|(proof, evals)| {
                izip!(0.., &node.preds, evals).for_each(|(wire_id, pred, eval)| match pred {
                    PredType::Source => {
                        assert_eq!(
                            witness.wires_in_ref()[wire_id]
                                .as_slice()
                                .mle(
                                    node.circuit.max_wires_in_num_vars.unwrap(),
                                    witness.instance_num_vars(),
                                )
                                .evaluate(&proof.point),
                            *eval
                        );
                    }
                    PredType::PredWire(out) => match out {
                        NodeOutputType::OutputLayer(id) => {
                            output_evals[*id].push(PointAndEval::new_from_ref(&proof.point, eval))
                        }
                        NodeOutputType::WireOut(id, wire_id) => {
                            wires_out_evals[*id]
                                .resize(*wire_id as usize + 1, PointAndEval::default());
                            wires_out_evals[*id][*wire_id as usize] =
                                PointAndEval::new_from_ref(&proof.point, eval);
                        }
                    },
                    _ => unimplemented!(),
                });
            });

            proof
        })
        .collect();

        Ok(IOPProof { gkr_proofs })
    }
}
