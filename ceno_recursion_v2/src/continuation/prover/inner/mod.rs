use std::sync::Arc;

use ceno_zkvm::scheme::ZKVMProof;
use continuations_v2::SC;
use eyre::Result;
use mpcs::{Basefold, BasefoldRSParams};
use openvm_poseidon2_air::POSEIDON2_WIDTH;
use openvm_stark_backend::{
    StarkEngine,
    keygen::types::{MultiStarkProvingKey, MultiStarkVerifyingKey},
    proof::Proof,
    prover::{CommittedTraceData, DeviceMultiStarkProvingKey, ProverBackend, ProvingContext},
};
use openvm_stark_sdk::config::baby_bear_poseidon2::{
    Digest, EF, F, default_duplex_sponge_recorder,
};
use verify_stark::pvs::DeferralPvs;

use crate::{
    circuit::{
        Circuit,
        inner::{InnerCircuit, InnerTraceGen, ProofsType},
    },
    system::{
        AggregationSubCircuit, RecursionField, RecursionVk, VerifierConfig, VerifierExternalData,
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
> {
    pk: Arc<MultiStarkProvingKey<SC>>,
    d_pk: DeviceMultiStarkProvingKey<PB>,
    vk: Arc<MultiStarkVerifyingKey<SC>>,

    agg_node_tracegen: T,

    child_vk: Arc<RecursionVk>,
    child_vk_pcs_data: CommittedTraceData<PB>,
    circuit: Arc<InnerCircuit<S>>,

    self_vk_pcs_data: Option<CommittedTraceData<PB>>,
}

impl<
    PB: ProverBackend<Val = F, Challenge = EF, Commitment = Digest>,
    S: AggregationSubCircuit + VerifierTraceGen<PB, SC>,
    T: InnerTraceGen<PB>,
> InnerAggregationProver<PB, S, T>
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
        let engine = Eg::new(system_params);
        let child_vk_pcs_data = verifier_circuit.commit_child_vk(&engine, &child_vk);
        let circuit = Arc::new(InnerCircuit::new(
            Arc::new(verifier_circuit),
            def_hook_commit.map(|d| d.into()),
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
        let engine = Eg::new(pk.params.clone());
        let child_vk_pcs_data = verifier_circuit.commit_child_vk(&engine, &child_vk);
        let circuit = Arc::new(InnerCircuit::new(
            Arc::new(verifier_circuit),
            def_hook_commit.map(|d| d.into()),
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

impl<
    PB: ProverBackend<Val = F, Challenge = EF, Commitment = Digest>,
    S: AggregationSubCircuit + VerifierTraceGen<PB, SC>,
    T: InnerTraceGen<PB>,
> InnerAggregationProver<PB, S, T>
where
    PB::Matrix: Clone,
{
    pub fn agg_prove_no_def<E: StarkEngine<SC = SC, PB = PB>>(
        &self,
        proofs: &[ZKVMProof<RecursionField, Basefold<RecursionField, BasefoldRSParams>>],
        child_vk_kind: ChildVkKind,
    ) -> Result<Proof<SC>> {
        let ctx = self.generate_proving_ctx(proofs, child_vk_kind, ProofsType::Vm, None);
        let engine = E::new(self.pk.params.clone());
        #[cfg(debug_assertions)]
        debug_constraints(&self.circuit, &ctx, &engine);
        let proof = engine.prove(&self.d_pk, ctx)?;
        #[cfg(debug_assertions)]
        engine.verify(&self.vk, &proof)?;
        Ok(proof)
    }

    fn generate_proving_ctx(
        &self,
        proofs: &[ZKVMProof<RecursionField, Basefold<RecursionField, BasefoldRSParams>>],
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

        let (pre_ctxs, poseidon2_compress_inputs) = self
            .agg_node_tracegen
            .generate_pre_verifier_subcircuit_ctxs(
                proofs,
                proofs_type,
                absent_trace_pvs,
                child_is_app,
                child_vk_pcs_data.commitment,
            );

        let poseidon2_permute_inputs: Vec<[F; POSEIDON2_WIDTH]> = vec![];
        let range_check_inputs = vec![];
        let mut external_data = VerifierExternalData {
            poseidon2_compress_inputs: &poseidon2_compress_inputs,
            poseidon2_permute_inputs: &poseidon2_permute_inputs,
            range_check_inputs: &range_check_inputs,
            required_heights: None,
            final_transcript_state: None,
        };

        let mut transcript = default_duplex_sponge_recorder();
        transcript_observe_label(&mut transcript, TranscriptLabel::Riscv.as_bytes());
        let subcircuit_ctxs = self
            .circuit
            .verifier_circuit
            .generate_proving_ctxs(
                child_vk,
                child_vk_pcs_data.clone(),
                proofs,
                &mut external_data,
                transcript,
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

    pub fn get_self_vk_pcs_data(&self) -> Option<CommittedTraceData<PB>>
    where
        CommittedTraceData<PB>: Clone,
    {
        self.self_vk_pcs_data.clone()
    }
}
