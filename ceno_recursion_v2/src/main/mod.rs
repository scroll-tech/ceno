mod air;
mod sumcheck;
mod trace;

use std::sync::Arc;

use ceno_zkvm::scheme::ZKVMChipProof;
use eyre::{Result, bail, eyre};
use openvm_cpu_backend::CpuBackend;
use openvm_poseidon2_air::POSEIDON2_WIDTH;
use openvm_stark_backend::{
    AirRef, FiatShamirTranscript, ReadOnlyTranscript, StarkProtocolConfig, TranscriptHistory,
    prover::AirProvingContext,
};
use openvm_stark_sdk::config::baby_bear_poseidon2::{BabyBearPoseidon2Config, EF, F};
use p3_field::PrimeCharacteristicRing;
use p3_matrix::dense::RowMajorMatrix;

use self::{
    air::MainAir,
    sumcheck::{
        MainSumcheckAir, MainSumcheckRecord, MainSumcheckRoundRecord, MainSumcheckTraceGenerator,
    },
    trace::{MainRecord, MainTraceGenerator},
};
use crate::{
    bus::{MainBus, MainExpressionClaimBus, MainSumcheckInputBus, MainSumcheckOutputBus},
    system::{
        AirModule, BusIndexManager, BusInventory, ChipTranscriptRange, GlobalCtxCpu, Preflight,
        RecursionField, RecursionProof, RecursionVk, TraceGenModule,
    },
    tower::convert_logup_claim,
    tracegen::{ModuleChip, RowMajorChip},
};

pub use air::MainCols;
pub use sumcheck::MainSumcheckCols;

#[derive(Clone)]
pub struct MainModule {
    main_bus: MainBus,
    sumcheck_input_bus: MainSumcheckInputBus,
    sumcheck_output_bus: MainSumcheckOutputBus,
    expression_claim_bus: MainExpressionClaimBus,
}

impl MainModule {
    pub fn new(b: &mut BusIndexManager, bus_inventory: BusInventory) -> Self {
        let _ = b;
        let main_bus = bus_inventory.main_bus;
        let sumcheck_input_bus = bus_inventory.main_sumcheck_input_bus;
        let sumcheck_output_bus = bus_inventory.main_sumcheck_output_bus;
        let expression_claim_bus = bus_inventory.main_expression_claim_bus;
        Self {
            main_bus,
            sumcheck_input_bus,
            sumcheck_output_bus,
            expression_claim_bus,
        }
    }

    fn collect_records(
        &self,
        _child_vk: &RecursionVk,
        proofs: &[RecursionProof],
        preflights: &[Preflight],
    ) -> Result<Vec<(MainRecord, MainSumcheckRecord)>> {
        if proofs.len() != preflights.len() {
            bail!(
                "proof/preflight length mismatch ({} proofs vs {} preflights)",
                proofs.len(),
                preflights.len()
            );
        }

        let mut paired = Vec::new();
        for (proof_idx, (proof, preflight)) in proofs.iter().zip(preflights).enumerate() {
            let mut chip_pf_iter = preflight.main.chips.iter();
            let mut saw_chip = false;
            for (&chip_idx, chip_instances) in &proof.chip_proofs {
                for (instance_idx, chip_proof) in chip_instances.iter().enumerate() {
                    saw_chip = true;
                    let pf_entry = chip_pf_iter
                        .next()
                        .ok_or_else(|| eyre!(
                            "missing main preflight entry for chip {chip_idx} instance {instance_idx}"
                        ))?;
                    if pf_entry.chip_idx != chip_idx || pf_entry.instance_idx != instance_idx {
                        bail!(
                            "main preflight chip mismatch: expected ({}, {}), got ({}, {})",
                            chip_idx,
                            instance_idx,
                            pf_entry.chip_idx,
                            pf_entry.instance_idx
                        );
                    }
                    let claim = input_layer_claim(chip_proof);
                    let (log, local_tidx) = preflight.transcript_log_for_tidx(pf_entry.tidx);
                    let mut ts = ReadOnlyTranscript::new(log, local_tidx);
                    record_main_transcript(&mut ts, chip_idx, chip_proof);

                    let main_record = MainRecord {
                        proof_idx,
                        idx: chip_idx,
                        tidx: pf_entry.tidx,
                        claim,
                    };
                    let sumcheck_record = build_sumcheck_record_from_chip(
                        proof_idx,
                        chip_idx,
                        claim,
                        chip_proof,
                        pf_entry.tidx,
                    );
                    paired.push((main_record, sumcheck_record));
                }
            }

            if !saw_chip {
                paired.push((
                    MainRecord {
                        proof_idx,
                        ..MainRecord::default()
                    },
                    MainSumcheckRecord::default(),
                ));
            }
        }

        if paired.is_empty() {
            paired.push((MainRecord::default(), MainSumcheckRecord::default()));
        }

        Ok(paired)
    }
}

impl AirModule for MainModule {
    fn num_airs(&self) -> usize {
        2
    }

    fn airs<SC: StarkProtocolConfig<F = F>>(&self) -> Vec<AirRef<SC>> {
        let main_air = MainAir {
            main_bus: self.main_bus,
            sumcheck_input_bus: self.sumcheck_input_bus,
            sumcheck_output_bus: self.sumcheck_output_bus,
            expression_claim_bus: self.expression_claim_bus,
        };
        let main_sumcheck_air = MainSumcheckAir {
            sumcheck_input_bus: self.sumcheck_input_bus,
            sumcheck_output_bus: self.sumcheck_output_bus,
        };
        vec![Arc::new(main_air) as AirRef<_>, Arc::new(main_sumcheck_air)]
    }
}

impl MainModule {
    pub fn run_preflight<TS>(
        &self,
        child_vk: &RecursionVk,
        proof: &RecursionProof,
        preflight: &mut Preflight,
        ts: &mut TS,
    ) where
        TS: FiatShamirTranscript<BabyBearPoseidon2Config>
            + TranscriptHistory<F = F, State = [F; POSEIDON2_WIDTH]>,
    {
        let _ = (self, child_vk);
        for (&chip_idx, chip_instances) in &proof.chip_proofs {
            for (instance_idx, chip_proof) in chip_instances.iter().enumerate() {
                let tidx = ts.len();
                record_main_transcript(ts, chip_idx, chip_proof);
                preflight.main.chips.push(ChipTranscriptRange {
                    chip_idx,
                    instance_idx,
                    tidx,
                });
            }
        }
    }
}

impl<SC: StarkProtocolConfig<F = F>> TraceGenModule<GlobalCtxCpu, CpuBackend<SC>> for MainModule {
    type ModuleSpecificCtx<'a> = ();

    fn generate_proving_ctxs(
        &self,
        child_vk: &RecursionVk,
        proofs: &[RecursionProof],
        preflights: &[Preflight],
        _ctx: &Self::ModuleSpecificCtx<'_>,
        required_heights: Option<&[usize]>,
    ) -> Option<Vec<AirProvingContext<CpuBackend<SC>>>> {
        let mut paired = self.collect_records(child_vk, proofs, preflights).ok()?;
        paired.sort_by_key(|(record, _)| (record.proof_idx, record.idx));
        let (main_records, sumcheck_records): (Vec<_>, Vec<_>) = paired.into_iter().unzip();
        let ctx = MainTraceCtx {
            main_records: &main_records,
            sumcheck_records: &sumcheck_records,
        };
        let chips = [MainModuleChip::Main, MainModuleChip::Sumcheck];
        let span = tracing::Span::current();
        let contexts = chips
            .into_iter()
            .enumerate()
            .map(|(idx, chip)| {
                let _guard = span.enter();
                chip.generate_proving_ctx(
                    &ctx,
                    required_heights.and_then(|heights| heights.get(idx).copied()),
                )
            })
            .collect::<Option<Vec<_>>>()?;

        Some(contexts)
    }
}

struct MainTraceCtx<'a> {
    main_records: &'a [MainRecord],
    sumcheck_records: &'a [MainSumcheckRecord],
}

enum MainModuleChip {
    Main,
    Sumcheck,
}

impl RowMajorChip<F> for MainModuleChip {
    type Ctx<'a> = MainTraceCtx<'a>;

    fn generate_trace(
        &self,
        ctx: &Self::Ctx<'_>,
        required_height: Option<usize>,
    ) -> Option<RowMajorMatrix<F>> {
        match self {
            MainModuleChip::Main => {
                MainTraceGenerator.generate_trace(&ctx.main_records, required_height)
            }
            MainModuleChip::Sumcheck => {
                MainSumcheckTraceGenerator.generate_trace(&ctx.sumcheck_records, required_height)
            }
        }
    }
}

fn input_layer_claim(chip_proof: &ZKVMChipProof<RecursionField>) -> EF {
    let layer_count = chip_proof
        .tower_proof
        .logup_specs_eval
        .iter()
        .map(|spec_layers| spec_layers.len())
        .chain(
            chip_proof
                .tower_proof
                .prod_specs_eval
                .iter()
                .map(|spec_layers| spec_layers.len()),
        )
        .max()
        .unwrap_or(0);
    if layer_count == 0 {
        return EF::ZERO;
    }
    convert_logup_claim(chip_proof, layer_count - 1)[0]
}

fn build_sumcheck_record_from_chip(
    proof_idx: usize,
    chip_idx: usize,
    claim: EF,
    chip_proof: &ZKVMChipProof<RecursionField>,
    tidx: usize,
) -> MainSumcheckRecord {
    let rounds = chip_proof
        .gkr_iop_proof
        .as_ref()
        .and_then(|proof| proof.0.first())
        .map(|layer| {
            layer
                .main
                .proof
                .proofs
                .iter()
                .map(|msg| {
                    let mut evals = [EF::ZERO; 3];
                    for (dst, src) in evals.iter_mut().zip(msg.evaluations.iter().take(3)) {
                        *dst = *src;
                    }
                    MainSumcheckRoundRecord { evaluations: evals }
                })
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();

    MainSumcheckRecord {
        proof_idx,
        idx: chip_idx,
        tidx,
        claim,
        rounds,
    }
}

pub(crate) fn record_main_transcript<TS>(
    ts: &mut TS,
    _chip_idx: usize,
    chip_proof: &ZKVMChipProof<RecursionField>,
) where
    TS: FiatShamirTranscript<BabyBearPoseidon2Config>,
{
    ts.observe_ext(input_layer_claim(chip_proof));
}
