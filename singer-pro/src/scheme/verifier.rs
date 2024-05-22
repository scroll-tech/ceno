use ff_ext::ExtensionField;
use gkr::{structs::PointAndEval, utils::MultilinearExtensionFromVectors};
use gkr_graph::structs::TargetEvaluations;
use itertools::{chain, Itertools};
use transcript::Transcript;

use crate::{error::ZKVMError, SingerAuxInfo, SingerCircuit, SingerWiresOutValues};

use super::{GKRGraphVerifierState, SingerProof};

pub fn verify<E: ExtensionField>(
    vm_circuit: &SingerCircuit<E>,
    vm_proof: SingerProof<E>,
    aux_info: &SingerAuxInfo,
    challenges: &[E],
    transcript: &mut Transcript<E>,
) -> Result<(), ZKVMError> {
    // TODO: Add PCS.
    let point = (0..2 * <E as ExtensionField>::DEGREE)
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

    let ram_load_product: E = ram_load.iter().map(|x| E::from_limbs(&x)).product();
    let ram_store_product = ram_store.iter().map(|x| E::from_limbs(&x)).product();
    if ram_load_product != ram_store_product {
        return Err(ZKVMError::VerifyError);
    }

    let rom_input_sum = rom_input
        .iter()
        .map(|x| {
            let l = x.len();
            let (den, num) = x.split_at(l / 2);
            (E::from_limbs(den), E::from_limbs(num))
        })
        .fold((E::ONE, E::ZERO), |acc, x| {
            (acc.0 * x.0, acc.0 * x.1 + acc.1 * x.0)
        });
    let rom_table_sum = rom_table
        .iter()
        .map(|x| {
            let l = x.len();
            let (den, num) = x.split_at(l / 2);
            (E::from_limbs(den), E::from_limbs(num))
        })
        .fold((E::ONE, E::ZERO), |acc, x| {
            (acc.0 * x.0, acc.0 * x.1 + acc.1 * x.0)
        });
    if rom_input_sum.0 * rom_table_sum.1 != rom_input_sum.1 * rom_table_sum.0 {
        return Err(ZKVMError::VerifyError);
    }

    let mut target_evals = TargetEvaluations(
        chain![ram_load, ram_store, rom_input, rom_table]
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
            E::BaseField::from(aux_info.program_output_len as u64)
        )
    }

    GKRGraphVerifierState::verify(
        &vm_circuit.0,
        &challenges,
        &target_evals,
        vm_proof.gkr_phase_proof,
        &aux_info.graph_aux_info,
        transcript,
    )?;

    Ok(())
}
