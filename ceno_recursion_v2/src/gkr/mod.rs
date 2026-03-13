//! # GKR Air Module
//!
//! The GKR protocol reduces a fractional sum claim $\sum_{y \in H_{\ell+n}}
//! \frac{\hat{p}(y)}{\hat{q}(y)} = 0$ to evaluation claims on the input layer polynomials at a
//! random point. This is done through a layer-by-layer recursive reduction, where each layer uses a
//! sumcheck protocol.
//!
//! The GKR Air Module verifies the [`GkrProof`](openvm_stark_backend::proof::GkrProof) struct and
//! consists of four AIRs:
//!
//! 1. **GkrInputAir** - Handles initial setup, coordinates other AIRs, and sends final claims to
//!    batch constraint module
//! 2. **GkrLayerAir** - Manages layer-by-layer GKR reduction (verifies
//!    [`verify_gkr`](openvm_stark_backend::verifier::fractional_sumcheck_gkr::verify_gkr))
//! 3. **GkrLayerSumcheckAir** - Executes sumcheck protocol for each layer (verifies
//!    [`verify_gkr_sumcheck`](openvm_stark_backend::verifier::fractional_sumcheck_gkr::verify_gkr_sumcheck))
//!
//! ## Architecture
//!
//! ```text
//!                                ┌─────────────────┐
//!                                │                 │───────────────────► TranscriptBus
//!                                │                 │
//!  GkrModuleBus ────────────────►│   GkrInputAir   │───────────────────► ExpBitsLenBus
//!                                │                 │
//!                                │                 │───────────────────► BatchConstraintModuleBus
//!                                └─────────────────┘
//!                                      ┆      ▲
//!                                      ┆      ┆
//!                     GkrLayerInputBus ┆      ┆ GkrLayerOutputBus
//!                                      ┆      ┆
//!                                      ▼      ┆
//!                             ┌─────────────────────────┐
//!                             │                         │──────────────► TranscriptBus
//!   ┌┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄│       GkrLayerAir       │
//!   ┆                         │                         │──────────────► XiRandomnessBus
//!   ┆                         └─────────────────────────┘
//!   ┆                                  ┆      ▲
//!   ┆                                  ┆      ┆
//!   ┆              GkrSumcheckInputBus ┆      ┆ GkrSumcheckOutputBus
//!   ┆                                  ┆      ┆
//!   ┆                                  ▼      ┆
//!   ┆ GkrSumcheckChallengeBus ┌─────────────────────────┐
//!   ┆┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄│                         │──────────────► TranscriptBus
//!   ┆                         │   GkrLayerSumcheckAir   │
//!   └┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄►│                         │──────────────► XiRandomnessBus
//!                             └─────────────────────────┘
//! ```

use std::sync::Arc;

use openvm_stark_backend::{
    AirRef, FiatShamirTranscript, StarkProtocolConfig, TranscriptHistory,
    keygen::types::MultiStarkVerifyingKey,
    proof::Proof,
    prover::{AirProvingContext, ColMajorMatrix, CpuBackend},
};
use openvm_stark_sdk::config::baby_bear_poseidon2::{BabyBearPoseidon2Config, EF, F};
use p3_field::PrimeCharacteristicRing;
use p3_matrix::dense::RowMajorMatrix;
use recursion_circuit::{
    primitives::exp_bits_len::ExpBitsLenTraceGenerator,
};
use strum::EnumCount;

use crate::{
    gkr::{
        bus::{GkrLayerInputBus, GkrLayerOutputBus},
        input::{GkrInputAir, GkrInputRecord, GkrInputTraceGenerator},
        layer::{
            GkrLayerAir, GkrLayerRecord, GkrLayerTraceGenerator, GkrLogupSumCheckClaimAir,
            GkrLogupSumCheckClaimTraceGenerator, GkrProdReadSumCheckClaimAir,
            GkrProdReadSumCheckClaimTraceGenerator, GkrProdWriteSumCheckClaimAir,
            GkrProdWriteSumCheckClaimTraceGenerator,
        },
        sumcheck::{GkrLayerSumcheckAir, GkrSumcheckRecord, GkrSumcheckTraceGenerator},
    },
    system::{
        AirModule, BusIndexManager, BusInventory, GlobalCtxCpu, Preflight, RecursionProof,
        RecursionVk, TraceGenModule, convert_proof_from_zkvm,
    },
    tracegen::RowMajorChip,
};

// Internal bus definitions
mod bus;
pub use bus::{
    GkrLogupClaimBus, GkrLogupClaimInputBus, GkrLogupClaimMessage, GkrLogupLayerChallengeMessage,
    GkrProdLayerChallengeMessage, GkrProdReadClaimBus, GkrProdReadClaimInputBus,
    GkrProdSumClaimMessage, GkrProdWriteClaimBus, GkrProdWriteClaimInputBus,
    GkrSumcheckChallengeBus, GkrSumcheckChallengeMessage, GkrSumcheckInputBus,
    GkrSumcheckInputMessage, GkrSumcheckOutputBus, GkrSumcheckOutputMessage,
};

// Sub-modules for different AIRs
pub mod input;
pub mod layer;
pub mod sumcheck;
pub struct GkrModule {
    // System Params
    l_skip: usize,
    logup_pow_bits: usize,
    // Global bus inventory
    bus_inventory: BusInventory,
    // Module buses
    layer_input_bus: GkrLayerInputBus,
    layer_output_bus: GkrLayerOutputBus,
    sumcheck_input_bus: GkrSumcheckInputBus,
    sumcheck_output_bus: GkrSumcheckOutputBus,
    sumcheck_challenge_bus: GkrSumcheckChallengeBus,
    prod_read_claim_input_bus: GkrProdReadClaimInputBus,
    prod_read_claim_bus: GkrProdReadClaimBus,
    prod_write_claim_input_bus: GkrProdWriteClaimInputBus,
    prod_write_claim_bus: GkrProdWriteClaimBus,
    logup_claim_input_bus: GkrLogupClaimInputBus,
    logup_claim_bus: GkrLogupClaimBus,
}

struct GkrBlobCpu {
    input_records: Vec<GkrInputRecord>,
    layer_records: Vec<GkrLayerRecord>,
    sumcheck_records: Vec<GkrSumcheckRecord>,
    mus_records: Vec<Vec<EF>>,
    q0_claims: Vec<EF>,
}

trait ToOpenVmProof {
    fn to_openvm_proof(&self) -> Proof<BabyBearPoseidon2Config>;
}

impl ToOpenVmProof for RecursionProof {
    fn to_openvm_proof(&self) -> Proof<BabyBearPoseidon2Config> {
        convert_proof_from_zkvm(self)
    }
}

impl ToOpenVmProof for Proof<BabyBearPoseidon2Config> {
    fn to_openvm_proof(&self) -> Proof<BabyBearPoseidon2Config> {
        self.clone()
    }
}

impl GkrModule {
    pub fn new(
        mvk: &MultiStarkVerifyingKey<BabyBearPoseidon2Config>,
        b: &mut BusIndexManager,
        bus_inventory: BusInventory,
    ) -> Self {
        GkrModule {
            l_skip: mvk.inner.params.l_skip,
            logup_pow_bits: mvk.inner.params.logup.pow_bits,
            bus_inventory,
            layer_input_bus: GkrLayerInputBus::new(b.new_bus_idx()),
            layer_output_bus: GkrLayerOutputBus::new(b.new_bus_idx()),
            sumcheck_input_bus: GkrSumcheckInputBus::new(b.new_bus_idx()),
            sumcheck_output_bus: GkrSumcheckOutputBus::new(b.new_bus_idx()),
            sumcheck_challenge_bus: GkrSumcheckChallengeBus::new(b.new_bus_idx()),
            prod_read_claim_input_bus: GkrProdReadClaimInputBus::new(b.new_bus_idx()),
            prod_read_claim_bus: GkrProdReadClaimBus::new(b.new_bus_idx()),
            prod_write_claim_input_bus: GkrProdWriteClaimInputBus::new(b.new_bus_idx()),
            prod_write_claim_bus: GkrProdWriteClaimBus::new(b.new_bus_idx()),
            logup_claim_input_bus: GkrLogupClaimInputBus::new(b.new_bus_idx()),
            logup_claim_bus: GkrLogupClaimBus::new(b.new_bus_idx()),
        }
    }

    #[tracing::instrument(level = "trace", skip_all)]
    pub fn run_preflight<TS>(
        &self,
        child_vk: &RecursionVk,
        proof: &RecursionProof,
        preflight: &mut Preflight,
        ts: &mut TS,
    ) where
        TS: FiatShamirTranscript<BabyBearPoseidon2Config> + TranscriptHistory,
    {
        let _ = (self, child_vk, proof, preflight);
        ts.observe_ext(EF::ZERO);
    }

}

impl AirModule for GkrModule {
    fn num_airs(&self) -> usize {
        GkrModuleChipDiscriminants::COUNT
    }

    fn airs<SC: StarkProtocolConfig<F = F>>(&self) -> Vec<AirRef<SC>> {
        let gkr_input_air = GkrInputAir {
            l_skip: self.l_skip,
            logup_pow_bits: self.logup_pow_bits,
            gkr_module_bus: self.bus_inventory.gkr_module_bus,
            bc_module_bus: self.bus_inventory.bc_module_bus,
            transcript_bus: self.bus_inventory.transcript_bus,
            exp_bits_len_bus: self.bus_inventory.exp_bits_len_bus,
            layer_input_bus: self.layer_input_bus,
            layer_output_bus: self.layer_output_bus,
        };

        let gkr_layer_air = GkrLayerAir {
            transcript_bus: self.bus_inventory.transcript_bus,
            layer_input_bus: self.layer_input_bus,
            layer_output_bus: self.layer_output_bus,
            sumcheck_input_bus: self.sumcheck_input_bus,
            sumcheck_output_bus: self.sumcheck_output_bus,
            sumcheck_challenge_bus: self.sumcheck_challenge_bus,
            prod_read_claim_input_bus: self.prod_read_claim_input_bus,
            prod_read_claim_bus: self.prod_read_claim_bus,
            prod_write_claim_input_bus: self.prod_write_claim_input_bus,
            prod_write_claim_bus: self.prod_write_claim_bus,
            logup_claim_input_bus: self.logup_claim_input_bus,
            logup_claim_bus: self.logup_claim_bus,
        };

        let gkr_prod_read_sum_air = GkrProdReadSumCheckClaimAir {
            transcript_bus: self.bus_inventory.transcript_bus,
            prod_claim_input_bus: self.prod_read_claim_input_bus,
            prod_claim_bus: self.prod_read_claim_bus,
        };

        let gkr_prod_write_sum_air = GkrProdWriteSumCheckClaimAir {
            transcript_bus: self.bus_inventory.transcript_bus,
            prod_claim_input_bus: self.prod_write_claim_input_bus,
            prod_claim_bus: self.prod_write_claim_bus,
        };

        let gkr_logup_sum_air = GkrLogupSumCheckClaimAir {
            transcript_bus: self.bus_inventory.transcript_bus,
            logup_claim_input_bus: self.logup_claim_input_bus,
            logup_claim_bus: self.logup_claim_bus,
        };

        let gkr_sumcheck_air = GkrLayerSumcheckAir::new(
            self.bus_inventory.transcript_bus,
            self.bus_inventory.xi_randomness_bus,
            self.sumcheck_input_bus,
            self.sumcheck_output_bus,
            self.sumcheck_challenge_bus,
        );

        vec![
            Arc::new(gkr_input_air) as AirRef<_>,
            Arc::new(gkr_layer_air) as AirRef<_>,
            Arc::new(gkr_prod_read_sum_air) as AirRef<_>,
            Arc::new(gkr_prod_write_sum_air) as AirRef<_>,
            Arc::new(gkr_logup_sum_air) as AirRef<_>,
            Arc::new(gkr_sumcheck_air) as AirRef<_>,
        ]
    }
}

impl GkrModule {
    #[tracing::instrument(skip_all)]
    fn generate_blob<P>(
        &self,
        proofs: &[P],
        preflights: &[&Preflight],
        exp_bits_len_gen: &ExpBitsLenTraceGenerator,
    ) -> GkrBlobCpu
    where
        P: ToOpenVmProof + Sync,
    {
        let _ = (self, proofs, preflights, exp_bits_len_gen);
        GkrBlobCpu {
            input_records: vec![],
            layer_records: vec![],
            sumcheck_records: vec![],
            mus_records: vec![],
            q0_claims: vec![],
        }
    }

}

impl<SC: StarkProtocolConfig<F = F>> TraceGenModule<GlobalCtxCpu, CpuBackend<SC>> for GkrModule {
    type ModuleSpecificCtx<'a> = ExpBitsLenTraceGenerator;

    #[tracing::instrument(skip_all)]
    fn generate_proving_ctxs(
        &self,
        child_vk: &RecursionVk,
        proofs: &[RecursionProof],
        preflights: &[Preflight],
        ctx: &ExpBitsLenTraceGenerator,
        required_heights: Option<&[usize]>,
    ) -> Option<Vec<AirProvingContext<CpuBackend<SC>>>> {
        let _ = (self, child_vk, proofs, preflights, ctx);
        let air_count = required_heights
            .map(|heights| heights.len())
            .unwrap_or_else(|| self.airs::<SC>().len());
        Some(
            (0..air_count)
                .map(|idx| {
                    let height = required_heights
                        .and_then(|heights| heights.get(idx).copied())
                        .unwrap_or(1);
                    zero_air_ctx(height)
                })
                .collect(),
        )
    }

}

// To reduce the number of structs and trait implementations, we collect them into a single enum
// with enum dispatch.
#[derive(strum_macros::Display, strum::EnumDiscriminants)]
#[strum_discriminants(derive(strum_macros::EnumCount))]
#[strum_discriminants(repr(usize))]
enum GkrModuleChip {
    Input,
    Layer,
    ProdReadClaim,
    ProdWriteClaim,
    LogupClaim,
    LayerSumcheck,
}

impl GkrModuleChip {
    fn index(&self) -> usize {
        GkrModuleChipDiscriminants::from(self) as usize
    }
}

impl RowMajorChip<F> for GkrModuleChip {
    type Ctx<'a> = GkrBlobCpu;

    #[tracing::instrument(
        name = "wrapper.generate_trace",
        level = "trace",
        skip_all,
        fields(air = %self)
    )]
    fn generate_trace(
        &self,
        blob: &Self::Ctx<'_>,
        required_height: Option<usize>,
    ) -> Option<RowMajorMatrix<F>> {
        use GkrModuleChip::*;
        match self {
            Input => GkrInputTraceGenerator
                .generate_trace(&(&blob.input_records, &blob.q0_claims), required_height),
            Layer => GkrLayerTraceGenerator.generate_trace(
                &(&blob.layer_records, &blob.mus_records, &blob.q0_claims),
                required_height,
            ),
            ProdReadClaim => GkrProdReadSumCheckClaimTraceGenerator
                .generate_trace(&(&blob.layer_records, &blob.mus_records), required_height),
            ProdWriteClaim => GkrProdWriteSumCheckClaimTraceGenerator
                .generate_trace(&(&blob.layer_records, &blob.mus_records), required_height),
            LogupClaim => GkrLogupSumCheckClaimTraceGenerator
                .generate_trace(&(&blob.layer_records, &blob.mus_records), required_height),
            LayerSumcheck => GkrSumcheckTraceGenerator.generate_trace(
                &(&blob.sumcheck_records, &blob.mus_records),
                required_height,
            ),
        }
    }
}

#[cfg(feature = "cuda")]
mod cuda_tracegen {
    use itertools::Itertools;
    use openvm_cuda_backend::GpuBackend;
    use openvm_stark_backend::p3_maybe_rayon::prelude::*;

    use super::*;
    use crate::{
        cuda::{GlobalCtxGpu, preflight::PreflightGpu, proof::ProofGpu, vk::VerifyingKeyGpu},
        tracegen::cuda::generate_gpu_proving_ctx,
    };

    impl TraceGenModule<GlobalCtxGpu, GpuBackend> for GkrModule {
        type ModuleSpecificCtx<'a> = ExpBitsLenTraceGenerator;

        #[tracing::instrument(skip_all)]
        fn generate_proving_ctxs(
            &self,
            child_vk: &VerifyingKeyGpu,
            proofs: &[ProofGpu],
            preflights: &[PreflightGpu],
            exp_bits_len_gen: &ExpBitsLenTraceGenerator,
            required_heights: Option<&[usize]>,
        ) -> Option<Vec<AirProvingContext<GpuBackend>>> {
            let proofs_cpu = proofs.iter().map(|proof| &proof.cpu).collect_vec();
            let preflights_cpu = preflights
                .iter()
                .map(|preflight| &preflight.cpu)
                .collect_vec();
            let blob = self.generate_blob(&proofs_cpu, &preflights_cpu, exp_bits_len_gen);
            let chips = [
                GkrModuleChip::Input,
                GkrModuleChip::Layer,
                GkrModuleChip::ProdReadClaim,
                GkrModuleChip::ProdWriteClaim,
                GkrModuleChip::LogupClaim,
                GkrModuleChip::LayerSumcheck,
            ];

            let span = tracing::Span::current();
            chips
                .par_iter()
                .map(|chip| {
                    let _guard = span.enter();
                    generate_gpu_proving_ctx(
                        chip,
                        &blob,
                        required_heights.map(|heights| heights[chip.index()]),
                    )
                })
                .collect::<Vec<_>>()
                .into_iter()
                .collect()
        }
    }
}

fn zero_air_ctx<SC: StarkProtocolConfig<F = F>>(
    height: usize,
) -> AirProvingContext<CpuBackend<SC>> {
    let rows = height.max(1);
    let matrix = RowMajorMatrix::new(vec![F::ZERO; rows], 1);
    AirProvingContext::simple_no_pis(ColMajorMatrix::from_row_major(&matrix))
}
