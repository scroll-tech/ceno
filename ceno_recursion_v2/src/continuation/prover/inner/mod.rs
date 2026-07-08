use std::{sync::Arc, time::Instant};

use eyre::Result;
#[cfg(test)]
use openvm_cpu_backend::CpuBackend;
use openvm_poseidon2_air::POSEIDON2_WIDTH;
use openvm_stark_backend::{
    StarkEngine, StarkProtocolConfig,
    keygen::types::{MultiStarkProvingKey, MultiStarkVerifyingKey},
    proof::Proof,
    prover::{
        AirProvingContext, CommittedTraceData, DeviceMultiStarkProvingKey, MatrixDimensions,
        ProverBackend, ProvingContext,
    },
};
use openvm_stark_sdk::config::baby_bear_poseidon2::{
    BabyBearPoseidon2Config, Digest, EF, F, default_duplex_sponge_recorder,
};
use verify_stark::pvs::DeferralPvs;

#[cfg(test)]
use crate::system::VerifierSubCircuit;
use crate::{
    circuit::{
        Circuit,
        inner::{InnerCircuit, InnerTraceGen, ProofsType},
    },
    system::{
        AggregationSubCircuit, RecursionProof, RecursionVk, VerifierConfig, VerifierExternalData,
        VerifierTraceGen,
    },
    utils::{TranscriptLabel, transcript_observe_label},
};

pub use continuations_v2::prover::ChildVkKind;
use continuations_v2::prover::debug_constraints;
use openvm_stark_backend::prover::DeviceDataTransporter;

pub use openvm_stark_backend::SystemParams;

/// Forked inner prover that will bridge Ceno ZKVM proofs with OpenVM recursion.
pub struct InnerAggregationProver<
    PB: ProverBackend<Val = F, Challenge = EF, Commitment = Digest>,
    S: AggregationSubCircuit + VerifierTraceGen<PB, SC>,
    T: InnerTraceGen<PB>,
    SC: StarkProtocolConfig<F = F, EF = EF, Digest = Digest> = BabyBearPoseidon2Config,
> {
    pk: Arc<MultiStarkProvingKey<SC>>,
    d_pk: DeviceMultiStarkProvingKey<PB>,
    vk: Arc<MultiStarkVerifyingKey<SC>>,

    agg_node_tracegen: T,

    child_vk: Arc<RecursionVk>,
    child_vk_pcs_data: Option<CommittedTraceData<PB>>,
    circuit: Arc<InnerCircuit<S>>,

    self_vk_pcs_data: Option<CommittedTraceData<PB>>,
}

impl<
    PB: ProverBackend<Val = F, Challenge = EF, Commitment = Digest>,
    S: AggregationSubCircuit + VerifierTraceGen<PB, SC>,
    T: InnerTraceGen<PB>,
    SC: StarkProtocolConfig<F = F, EF = EF, Digest = Digest>,
> InnerAggregationProver<PB, S, T, SC>
{
    pub fn new<Eg: StarkEngine<SC = SC, PB = PB>>(
        child_vk: Arc<RecursionVk>,
        system_params: SystemParams,
        is_self_recursive: bool,
        def_hook_commit: Option<Digest>,
    ) -> Self {
        let verifier_circuit = S::new(
            child_vk.clone(),
            VerifierConfig {
                continuations_enabled: true,
                ..Default::default()
            },
        );
        let instance_public_value_indices =
            Arc::new(build_instance_public_value_indices(&child_vk));
        let engine = Eg::new(system_params);
        let child_vk_pcs_data = verifier_circuit.commit_child_vk(&engine, &child_vk);
        let circuit = Arc::new(InnerCircuit::new(
            Arc::new(verifier_circuit),
            def_hook_commit.map(|d| d.into()),
            instance_public_value_indices,
        ));
        let (pk, vk) = engine.keygen(&circuit.airs());
        let d_pk = engine.device().transport_pk_to_device(&pk);
        let self_vk_pcs_data = if is_self_recursive {
            unimplemented!(
                "Self-recursive inner prover support requires converting the local VK into RecursionVk"
            )
        } else {
            None
        };
        let agg_node_tracegen = T::new(def_hook_commit.is_some());
        Self {
            pk: Arc::new(pk),
            d_pk,
            vk: Arc::new(vk),
            agg_node_tracegen,
            child_vk,
            child_vk_pcs_data,
            circuit,
            self_vk_pcs_data,
        }
    }

    #[allow(dead_code)]
    pub fn from_pk<Eg: StarkEngine<SC = SC, PB = PB>>(
        child_vk: Arc<RecursionVk>,
        pk: Arc<MultiStarkProvingKey<SC>>,
        is_self_recursive: bool,
        def_hook_commit: Option<Digest>,
    ) -> Self {
        let verifier_circuit = S::new(
            child_vk.clone(),
            VerifierConfig {
                continuations_enabled: true,
                ..Default::default()
            },
        );
        let instance_public_value_indices =
            Arc::new(build_instance_public_value_indices(&child_vk));
        let engine = Eg::new(pk.params.clone());
        let child_vk_pcs_data = verifier_circuit.commit_child_vk(&engine, &child_vk);
        let circuit = Arc::new(InnerCircuit::new(
            Arc::new(verifier_circuit),
            def_hook_commit.map(|d| d.into()),
            instance_public_value_indices,
        ));
        let vk = Arc::new(pk.get_vk());
        let d_pk = engine.device().transport_pk_to_device(&pk);
        let self_vk_pcs_data = if is_self_recursive {
            unimplemented!(
                "Self-recursive inner prover support requires converting the local VK into RecursionVk"
            )
        } else {
            None
        };
        let agg_node_tracegen = T::new(def_hook_commit.is_some());
        Self {
            pk,
            d_pk,
            vk,
            agg_node_tracegen,
            child_vk,
            child_vk_pcs_data,
            circuit,
            self_vk_pcs_data,
        }
    }
}

fn build_instance_public_value_indices(child_vk: &RecursionVk) -> Vec<Vec<usize>> {
    (0..child_vk.circuit_vks.len())
        .map(|air_idx| {
            child_vk
                .circuit_index_to_name
                .get(&air_idx)
                .and_then(|name| child_vk.circuit_vks.get(name))
                .map(|circuit_vk| {
                    circuit_vk
                        .get_cs()
                        .zkvm_v1_css
                        .instance
                        .iter()
                        .map(|instance_value| instance_value.0)
                        .collect()
                })
                .unwrap_or_default()
        })
        .collect()
}

impl<
    PB: ProverBackend<Val = F, Challenge = EF, Commitment = Digest>,
    S: AggregationSubCircuit + VerifierTraceGen<PB, SC>,
    T: InnerTraceGen<PB>,
    SC: StarkProtocolConfig<F = F, EF = EF, Digest = Digest>,
> InnerAggregationProver<PB, S, T, SC>
where
    PB::Matrix: Clone,
    PB::Commitment: Default,
{
    pub fn agg_prove_no_def<E: StarkEngine<SC = SC, PB = PB>>(
        &self,
        proofs: &[RecursionProof],
        child_vk_kind: ChildVkKind,
    ) -> Result<Proof<SC>> {
        let tracegen_start = Instant::now();
        let ctx = self.generate_proving_ctx(proofs, child_vk_kind, ProofsType::Vm, None);
        tracing::info!(
            elapsed_ms = tracegen_start.elapsed().as_secs_f64() * 1000.0,
            num_traces = ctx.per_trace.len(),
            "generated recursion proving context"
        );
        if tracing::enabled!(tracing::Level::INFO) {
            trace_heights_tracing_info::<PB, SC>(&ctx.per_trace, &self.circuit.airs());
        }

        let engine = E::new(self.pk.params.clone());
        #[cfg(debug_assertions)]
        if std::env::var_os("CENO_REC_V2_DEBUG_CONSTRAINTS").is_some() {
            debug_constraints(&self.circuit, &ctx, &engine);
        }
        let prove_start = Instant::now();
        let proof = engine.prove(&self.d_pk, ctx)?;
        tracing::info!(
            elapsed_ms = prove_start.elapsed().as_secs_f64() * 1000.0,
            "proved recursion aggregation"
        );
        self.verify_proof::<E>(&proof)?;
        Ok(proof)
    }

    fn generate_proving_ctx(
        &self,
        proofs: &[RecursionProof],
        child_vk_kind: ChildVkKind,
        proofs_type: ProofsType,
        absent_trace_pvs: Option<(DeferralPvs<F>, bool)>,
    ) -> ProvingContext<PB> {
        assert!(proofs.len() <= self.circuit.verifier_circuit.max_num_proofs());

        let (child_vk, child_vk_pcs_data) = match child_vk_kind {
            ChildVkKind::RecursiveSelf => {
                unimplemented!("RecursiveSelf proving is not wired for RecursionVk yet")
            }
            _ => (&self.child_vk, self.child_vk_pcs_data.clone()),
        };
        let child_is_app = matches!(child_vk_kind, ChildVkKind::App);

        let mut transcript = default_duplex_sponge_recorder();
        transcript_observe_label(&mut transcript, TranscriptLabel::Riscv.as_bytes());

        let child_dag_commit = child_vk_pcs_data
            .as_ref()
            .map(|data| data.commitment.clone())
            .unwrap_or_default();

        let (pre_ctxs, poseidon2_compress_inputs, subcircuit_initial_transcripts) = self
            .agg_node_tracegen
            .generate_pre_verifier_subcircuit_ctxs(
                proofs,
                proofs_type,
                absent_trace_pvs,
                child_is_app,
                child_vk,
                child_dag_commit,
                transcript,
            );

        let poseidon2_permute_inputs: Vec<[F; POSEIDON2_WIDTH]> = vec![];
        let range_check_inputs = vec![];
        let power_check_inputs = vec![];
        let mut external_data = VerifierExternalData {
            poseidon2_compress_inputs: &poseidon2_compress_inputs,
            poseidon2_permute_inputs: &poseidon2_permute_inputs,
            range_check_inputs: &range_check_inputs,
            power_check_inputs: &power_check_inputs,
            required_heights: None,
            final_transcript_state: None,
        };

        let subcircuit_ctxs = self
            .circuit
            .verifier_circuit
            .generate_proving_ctxs(
                child_vk,
                child_vk_pcs_data.clone(),
                proofs,
                &mut external_data,
                subcircuit_initial_transcripts,
            )
            .expect("verifier sub-circuit ctx generation");

        let post_ctxs = self
            .agg_node_tracegen
            .generate_post_verifier_subcircuit_ctxs(proofs, proofs_type, child_is_app);

        ProvingContext {
            per_trace: pre_ctxs
                .into_iter()
                .chain(subcircuit_ctxs)
                .chain(post_ctxs)
                .enumerate()
                .collect(),
        }
    }

    pub fn get_vk(&self) -> Arc<MultiStarkVerifyingKey<SC>> {
        self.vk.clone()
    }

    pub fn verify_proof<E: StarkEngine<SC = SC, PB = PB>>(&self, proof: &Proof<SC>) -> Result<()> {
        let verify_start = Instant::now();
        let engine = E::new(self.vk.inner.params.clone());
        engine.verify(&self.vk, proof)?;
        tracing::info!(
            elapsed_ms = verify_start.elapsed().as_secs_f64() * 1000.0,
            "verified recursion aggregation proof"
        );
        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn air_names(&self) -> Vec<String> {
        <InnerCircuit<S> as Circuit<SC>>::airs(self.circuit.as_ref())
            .iter()
            .map(|air| air.name().to_string())
            .collect()
    }

    pub fn get_self_vk_pcs_data(&self) -> Option<CommittedTraceData<PB>>
    where
        CommittedTraceData<PB>: Clone,
    {
        self.self_vk_pcs_data.clone()
    }
}

#[cfg(test)]
impl<const MAX_NUM_PROOFS: usize, T>
    InnerAggregationProver<
        CpuBackend<BabyBearPoseidon2Config>,
        VerifierSubCircuit<MAX_NUM_PROOFS>,
        T,
    >
where
    T: InnerTraceGen<CpuBackend<BabyBearPoseidon2Config>>,
{
    pub(crate) fn debug_with_preflight_mutation<Eg, M>(
        &self,
        proofs: &[RecursionProof],
        child_vk_kind: ChildVkKind,
        mutate: M,
    ) -> bool
    where
        Eg: StarkEngine<SC = BabyBearPoseidon2Config, PB = CpuBackend<BabyBearPoseidon2Config>>,
        M: FnOnce(&mut [crate::system::Preflight]) -> bool,
    {
        assert!(proofs.len() <= self.circuit.verifier_circuit.max_num_proofs());

        let (child_vk, child_vk_pcs_data) = match child_vk_kind {
            ChildVkKind::RecursiveSelf => {
                unimplemented!("RecursiveSelf proving is not wired for RecursionVk yet")
            }
            _ => (&self.child_vk, self.child_vk_pcs_data.clone()),
        };
        let child_is_app = matches!(child_vk_kind, ChildVkKind::App);

        let mut transcript = default_duplex_sponge_recorder();
        transcript_observe_label(&mut transcript, TranscriptLabel::Riscv.as_bytes());
        let child_dag_commit = child_vk_pcs_data
            .as_ref()
            .map(|data| data.commitment.clone())
            .unwrap_or_default();

        let (pre_ctxs, poseidon2_compress_inputs, subcircuit_initial_transcripts) = self
            .agg_node_tracegen
            .generate_pre_verifier_subcircuit_ctxs(
                proofs,
                ProofsType::Vm,
                None,
                child_is_app,
                child_vk,
                child_dag_commit,
                transcript,
            );
        let poseidon2_permute_inputs: Vec<[F; POSEIDON2_WIDTH]> = vec![];
        let range_check_inputs = vec![];
        let power_check_inputs = vec![];
        let external_data = VerifierExternalData {
            poseidon2_compress_inputs: &poseidon2_compress_inputs,
            poseidon2_permute_inputs: &poseidon2_permute_inputs,
            range_check_inputs: &range_check_inputs,
            power_check_inputs: &power_check_inputs,
            required_heights: None,
            final_transcript_state: None,
        };

        let mut preflights = proofs
            .iter()
            .zip(subcircuit_initial_transcripts)
            .map(|(proof, sponge)| {
                self.circuit
                    .verifier_circuit
                    .test_run_preflight(sponge, child_vk, proof)
            })
            .collect::<Vec<_>>();
        if !mutate(&mut preflights) {
            return false;
        }

        let subcircuit_ctxs = self
            .circuit
            .verifier_circuit
            .test_generate_proving_ctxs_from_preflights::<BabyBearPoseidon2Config>(
                child_vk,
                proofs,
                &preflights,
                &external_data,
            );
        let post_ctxs = self
            .agg_node_tracegen
            .generate_post_verifier_subcircuit_ctxs(proofs, ProofsType::Vm, child_is_app);
        let ctx = ProvingContext {
            per_trace: pre_ctxs
                .into_iter()
                .chain(subcircuit_ctxs)
                .chain(post_ctxs)
                .enumerate()
                .collect(),
        };
        let engine = Eg::new(self.pk.params.clone());
        debug_constraints(&self.circuit, &ctx, &engine);
        true
    }
}

fn trace_heights_tracing_info<PB: ProverBackend, SC: openvm_stark_backend::StarkProtocolConfig>(
    ctxs: &[(usize, AirProvingContext<PB>)],
    airs: &[openvm_stark_backend::AirRef<SC>],
) {
    let mut total_cells = 0usize;
    let mut total_width = 0usize;
    for ((air_id, ctx), air) in ctxs.iter().zip(airs) {
        let height = ctx.common_main.height();
        let width = ctx.common_main.width();
        let cells = height * width;
        tracing::info!(
            air_id,
            air_name = air.name(),
            height,
            width,
            cells,
            "recursion trace dimensions"
        );
        total_cells += cells;
        total_width += width;
    }
    tracing::info!(total_cells, total_width, "recursion trace totals");
}
