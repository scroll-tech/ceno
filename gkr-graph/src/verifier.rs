use gkr::structs::{IOPProverPhase2Message, PointAndEval};
use goldilocks::SmallField;
use itertools::izip;
use std::mem;
use transcript::Transcript;

use crate::{
    error::GKRGraphError,
    structs::{
        CircuitGraph, CircuitGraphAuxInfo, IOPProof, IOPVerifierState, NodeOutputType, PredType,
        TargetEvaluations,
    },
};

impl<F: SmallField> IOPVerifierState<F> {
    pub fn verify(
        circuit: &CircuitGraph<F>,
        challenges: &[F],
        target_evals: &TargetEvaluations<F>,
        proof: &IOPProof<F>,
        aux_info: &CircuitGraphAuxInfo,
        transcript: &mut Transcript<F>,
    ) -> Result<(), GKRGraphError> {
        assert_eq!(target_evals.0.len(), circuit.targets.len());

        let mut output_evals = vec![vec![]; circuit.nodes.len()];
        let mut wires_out_evals = vec![vec![]; circuit.nodes.len()];
        izip!(&circuit.targets, &target_evals.0).for_each(|(target, eval)| match target {
            NodeOutputType::OutputLayer(id) => output_evals[*id].push(eval.clone()),
            NodeOutputType::WireOut(id, _) => wires_out_evals[*id].push(eval.clone()),
        });

        for ((id, node, instance_num_vars), proof) in izip!(
            0..circuit.nodes.len(),
            &circuit.nodes,
            &aux_info.instance_num_vars,
        )
        .rev()
        .zip(&proof.gkr_proofs)
        {
            let _claim = gkr::structs::IOPVerifierState::verify_parallel(
                &node.circuit,
                challenges,
                &mem::take(&mut output_evals[id]),
                &mem::take(&mut wires_out_evals[id]),
                proof,
                *instance_num_vars,
                transcript,
            )?;

            let IOPProverPhase2Message {
                sumcheck_proofs,
                sumcheck_eval_values,
            } = &proof.sumcheck_proofs.last().unwrap().1;
            izip!(sumcheck_proofs, sumcheck_eval_values).for_each(|(proof, evals)| {
                izip!(0.., &node.preds, evals).for_each(|(_, pred, eval)| match pred {
                    PredType::Source => {}
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
                    _ => unreachable!(),
                });
            });
        }

        Ok(())
    }
}
