use std::sync::Arc;

use ceno_zkvm::scheme::ZKVMProof;
use continuations_v2::{SC};
use eyre::Result;
use ff_ext::BabyBearExt4;
use mpcs::{Basefold, BasefoldRSParams};
use openvm_stark_backend::{
    keygen::types::{MultiStarkProvingKey, MultiStarkVerifyingKey},
    proof::Proof,
    prover::{CommittedTraceData, DeviceMultiStarkProvingKey, ProverBackend, ProvingContext},
    StarkEngine, SystemParams,
};
use openvm_stark_sdk::config::baby_bear_poseidon2::{
    default_duplex_sponge_recorder, Digest, EF, F,
};
use recursion_circuit::system::{
    AggregationSubCircuit, CachedTraceCtx, VerifierExternalData, VerifierTraceGen,
};
use verify_stark::pvs::DeferralPvs;

use continuations_v2::circuit::inner::{InnerCircuit, InnerTraceGen, ProofsType};

pub use continuations_v2::prover::ChildVkKind;
use continuations_v2::prover::debug_constraints;

type RecursionField = BabyBearExt4;

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

    child_vk: Arc<MultiStarkVerifyingKey<SC>>,
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
        _child_vk: Arc<MultiStarkVerifyingKey<SC>>,
        _system_params: SystemParams,
        _is_self_recursive: bool,
        _def_hook_commit: Option<Digest>,
    ) -> Self {
        unimplemented!("InnerAggregationProver::new placeholder")
    }

    #[allow(dead_code)]
    pub fn from_pk<Eg: StarkEngine<SC = SC, PB = PB>>(
        _child_vk: Arc<MultiStarkVerifyingKey<SC>>,
        _pk: Arc<MultiStarkProvingKey<SC>>,
        _is_self_recursive: bool,
        _def_hook_commit: Option<Digest>,
    ) -> Self {
        unimplemented!("InnerAggregationProver::from_pk placeholder")
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
        if tracing::enabled!(tracing::Level::DEBUG) {
            // TODO enable trace height
            //     trace_heights_tracing_info::<_, SC>(&ctx.per_trace, &self.circuit.airs());
        }

        let engine = E::new(self.pk.params.clone());
        // TODO(ceno-recursion): wire up local debug hooks once we port them.
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

        let vm_proofs = Self::materialize_vm_proofs(proofs);

        let (child_vk, child_dag_commit) = match child_vk_kind {
            ChildVkKind::RecursiveSelf => (
                &self.vk,
                self.self_vk_pcs_data
                    .clone()
                    .expect("self recursive proofs need cached vk pcs data"),
            ),
            _ => (&self.child_vk, self.child_vk_pcs_data.clone()),
        };
        let child_is_app = matches!(child_vk_kind, ChildVkKind::App);

        let (pre_ctxs, poseidon2_inputs) = self.agg_node_tracegen.generate_pre_verifier_subcircuit_ctxs(
            &vm_proofs,
            proofs_type,
            absent_trace_pvs,
            child_is_app,
            child_dag_commit.commitment,
        );

        let range_check_inputs = vec![];
        let mut external_data = VerifierExternalData {
            poseidon2_compress_inputs: &poseidon2_inputs,
            range_check_inputs: &range_check_inputs,
            required_heights: None,
            final_transcript_state: None,
        };

        let cached_trace_ctx = CachedTraceCtx::PcsData(child_dag_commit);
        let subcircuit_ctxs = self
            .circuit
            .verifier_circuit
            .generate_proving_ctxs(
                child_vk,
                cached_trace_ctx,
                &vm_proofs,
                &mut external_data,
                default_duplex_sponge_recorder(),
            )
            .expect("verifier sub-circuit ctx generation");
        let post_ctxs =
            self.agg_node_tracegen
                .generate_post_verifier_subcircuit_ctxs(&vm_proofs, proofs_type, child_is_app);

        ProvingContext {
            per_trace: pre_ctxs
                .into_iter()
                .chain(subcircuit_ctxs)
                .chain(post_ctxs)
                .enumerate()
                .collect(),
        }
    }

    fn materialize_vm_proofs(
        _proofs: &[ZKVMProof<RecursionField, Basefold<RecursionField, BasefoldRSParams>>],
    ) -> Vec<Proof<SC>> {
        unimplemented!("Bridge ZKVMProof -> Proof<SC> conversion is not implemented yet");
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
