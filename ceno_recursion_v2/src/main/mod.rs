mod air;
mod sumcheck;
mod trace;

use std::{collections::BTreeMap, sync::Arc};

use ceno_zkvm::scheme::ZKVMChipProof;
use eyre::{Result, bail, eyre};
use openvm_cpu_backend::CpuBackend;
use openvm_poseidon2_air::POSEIDON2_WIDTH;
use openvm_stark_backend::{
    AirRef, FiatShamirTranscript, StarkProtocolConfig, TranscriptHistory, prover::AirProvingContext,
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
    bus::{
        MainBus, MainExpressionClaimBus, MainSumcheckInputBus, MainSumcheckOutputBus, TranscriptBus,
    },
    system::{
        AirModule, BusIndexManager, BusInventory, ChipTranscriptRange, GlobalCtxCpu, Preflight,
        RecursionField, RecursionProof, RecursionVk, TraceGenModule,
    },
    tower::build_gkr_blob,
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
    transcript_bus: TranscriptBus,
}

impl MainModule {
    pub fn new(b: &mut BusIndexManager, bus_inventory: BusInventory) -> Self {
        let _ = b;
        let main_bus = bus_inventory.main_bus;
        let sumcheck_input_bus = bus_inventory.main_sumcheck_input_bus;
        let sumcheck_output_bus = bus_inventory.main_sumcheck_output_bus;
        let expression_claim_bus = bus_inventory.main_expression_claim_bus;
        let transcript_bus = bus_inventory.transcript_bus;
        Self {
            main_bus,
            sumcheck_input_bus,
            sumcheck_output_bus,
            expression_claim_bus,
            transcript_bus,
        }
    }

    fn collect_records(
        &self,
        child_vk: &RecursionVk,
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

        let tower_blob = build_gkr_blob(child_vk, proofs, preflights)?;
        let tower_inputs: BTreeMap<(usize, usize), _> = tower_blob
            .input_records
            .iter()
            .map(|record| ((record.proof_idx, record.chip_idx), record))
            .collect();

        let mut paired = Vec::new();
        for (proof_idx, (proof, preflight)) in proofs.iter().zip(preflights).enumerate() {
            let mut saw_chip = false;
            let sorted_idx_by_chip: BTreeMap<usize, usize> = preflight
                .proof_shape
                .sorted_trace_vdata
                .iter()
                .enumerate()
                .map(|(sorted_idx, (chip_id, _))| (*chip_id, sorted_idx))
                .collect();
            let mut sorted_pf_entries: Vec<_> = preflight.main.chips.iter().collect();
            sorted_pf_entries.sort_by_key(|entry| {
                (
                    sorted_idx_by_chip
                        .get(&entry.chip_id)
                        .copied()
                        .unwrap_or(usize::MAX),
                    entry.instance_idx,
                )
            });

            for (entry_idx, pf_entry) in sorted_pf_entries.into_iter().enumerate() {
                let chip_id = pf_entry.chip_id;
                let chip_idx = sorted_idx_by_chip
                    .get(&chip_id)
                    .copied()
                    .ok_or_else(|| eyre!("missing proof-shape index for chip {chip_id}"))?;
                eyre::ensure!(
                    chip_idx == entry_idx,
                    "proof-local chip index mismatch for chip {chip_id}: proof-shape={chip_idx}, main-row={entry_idx}"
                );
                let instance_idx = pf_entry.instance_idx;
                let chip_instances = proof
                    .chip_proofs
                    .get(&chip_id)
                    .ok_or_else(|| eyre!("missing chip proof instances for chip {chip_id}"))?;
                let chip_proof = chip_instances.get(instance_idx).ok_or_else(|| {
                    eyre!("missing chip proof instance {instance_idx} for chip {chip_id}")
                })?;
                let tower_input = tower_inputs.get(&(proof_idx, chip_idx)).ok_or_else(|| {
                    eyre!("missing tower input record for proof {proof_idx} chip_idx {chip_idx}")
                })?;
                saw_chip = true;

                let claim = tower_input.input_layer_claim;
                let global_tidx = tower_input.final_tidx;
                let sumcheck_record = build_sumcheck_record_from_chip(
                    proof_idx,
                    chip_idx,
                    claim,
                    chip_proof,
                    global_tidx,
                );
                let main_record = MainRecord {
                    proof_idx,
                    idx: chip_idx,
                    chip_idx,
                    has_tower: tower_input.num_layers > 0,
                    has_sumcheck: !sumcheck_record.rounds.is_empty(),
                    tidx: global_tidx,
                    claim,
                };
                paired.push((main_record, sumcheck_record));
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
            transcript_bus: self.transcript_bus,
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
        for (&chip_id, chip_instances) in &proof.chip_proofs {
            for (instance_idx, chip_proof) in chip_instances.iter().enumerate() {
                let tidx = ts.len();
                record_main_transcript(ts, input_layer_claim(chip_proof));
                preflight.main.chips.push(ChipTranscriptRange {
                    chip_id,
                    instance_idx,
                    tidx,
                    fork_idx: 0, // unused in forked flow
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
    let _ = chip_proof;
    EF::ZERO
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

pub(crate) fn record_main_transcript<TS>(ts: &mut TS, claim: EF)
where
    TS: FiatShamirTranscript<BabyBearPoseidon2Config>,
{
    ts.observe_ext(claim);
}
