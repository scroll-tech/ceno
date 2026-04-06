//! Local fork-aware TranscriptAir.
//!
//! Copied from upstream `recursion_circuit::transcript::transcript::air` and extended with
//! fork support.  The key additions:
//!
//! * **`is_fork_start`** column — marks the first row of a forked transcript chain.
//!   When set, the sponge state is initialised from the provided initial fork state.
//!
//! * **`fork_id`** column — identifies which fork this row belongs to.
//!   Fork rows use 0-based identifiers (0..N-1) across per-chip forks.
//!
//! Fork rows otherwise follow upstream transcript constraints.

use core::borrow::Borrow;

use openvm_circuit_primitives::{
    SubAir,
    utils::{and, assert_array_eq, not, or},
};
use openvm_stark_backend::{
    BaseAirWithPublicValues, PartitionedBaseAir, interaction::InteractionBuilder,
};
use openvm_stark_sdk::config::baby_bear_poseidon2::D_EF;
use p3_air::{Air, AirBuilder, BaseAir};
use p3_field::{Field, PrimeCharacteristicRing};
use p3_matrix::Matrix;
use recursion_circuit::{
    subairs::nested_for_loop::{NestedForLoopIoCols, NestedForLoopSubAir},
    transcript::poseidon2::{CHUNK, POSEIDON2_WIDTH},
};

use crate::bus::{
    ForkedTranscriptBus, ForkedTranscriptBusMessage, TranscriptBus, TranscriptBusMessage,
};
use recursion_circuit::bus::{
    FinalTranscriptStateBus, FinalTranscriptStateMessage, Poseidon2PermuteBus,
    Poseidon2PermuteMessage,
};

// ── Column layout ─────────────────────────────────────────────────────────────

#[repr(C)]
#[derive(Debug)]
pub struct ForkedTranscriptCols<T> {
    // --- original fields (same layout as upstream TranscriptCols) ---
    pub proof_idx: T,
    pub is_proof_start: T,

    pub tidx: T,
    /// Indicator for sample/observe.
    pub is_sample: T,
    /// 0/1 indicators for positions being absorbed/squeezed.
    pub mask: [T; CHUNK],

    /// The poseidon2 state.
    pub prev_state: [T; POSEIDON2_WIDTH],
    pub post_state: [T; POSEIDON2_WIDTH],

    // --- fork extensions ---
    /// 1 on the first row of a forked transcript chain.
    pub is_fork_start: T,
    /// Fork identifier (0-based across forked chip transcripts).
    pub fork_id: T,
}

impl<T: Copy> ForkedTranscriptCols<T> {
    pub const fn width() -> usize {
        // proof_idx, is_proof_start, tidx, is_sample = 4
        // mask = CHUNK
        // prev_state = POSEIDON2_WIDTH
        // post_state = POSEIDON2_WIDTH
        // is_fork_start, fork_id = 2
        4 + CHUNK + 2 * POSEIDON2_WIDTH + 2
    }
}

impl<T: Copy> core::borrow::Borrow<ForkedTranscriptCols<T>> for [T] {
    fn borrow(&self) -> &ForkedTranscriptCols<T> {
        debug_assert!(self.len() >= ForkedTranscriptCols::<T>::width());
        let ptr = self.as_ptr() as *const ForkedTranscriptCols<T>;
        unsafe { &*ptr }
    }
}

impl<T: Copy> core::borrow::BorrowMut<ForkedTranscriptCols<T>> for [T] {
    fn borrow_mut(&mut self) -> &mut ForkedTranscriptCols<T> {
        debug_assert!(self.len() >= ForkedTranscriptCols::<T>::width());
        let ptr = self.as_mut_ptr() as *mut ForkedTranscriptCols<T>;
        unsafe { &mut *ptr }
    }
}

// ── AIR ───────────────────────────────────────────────────────────────────────

pub struct ForkedTranscriptAir {
    pub transcript_bus: TranscriptBus,
    pub forked_transcript_bus: ForkedTranscriptBus,
    pub poseidon2_permute_bus: Poseidon2PermuteBus,
    pub final_state_bus: Option<FinalTranscriptStateBus>,
}

impl<F: Field> BaseAir<F> for ForkedTranscriptAir {
    fn width(&self) -> usize {
        ForkedTranscriptCols::<F>::width()
    }
}

impl<F: Field> BaseAirWithPublicValues<F> for ForkedTranscriptAir {}
impl<F: Field> PartitionedBaseAir<F> for ForkedTranscriptAir {}

impl<AB: AirBuilder + InteractionBuilder> Air<AB> for ForkedTranscriptAir {
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let (local, next) = (
            main.row_slice(0).expect("window should have two elements"),
            main.row_slice(1).expect("window should have two elements"),
        );
        let local: &ForkedTranscriptCols<AB::Var> = (*local).borrow();
        let next: &ForkedTranscriptCols<AB::Var> = (*next).borrow();

        ///////////////////////////////////////////////////////////////////////
        // Validity / structural constraints
        ///////////////////////////////////////////////////////////////////////
        let is_valid = local.mask[0];
        let next_valid = next.mask[0];

        // is_proof_start and is_fork_start are mutually exclusive booleans
        builder.assert_bool(local.is_proof_start);
        builder.assert_bool(local.is_fork_start);
        // A row is a "chain start" if either is_proof_start or is_fork_start
        let is_chain_start: AB::Expr = local.is_proof_start.into() + local.is_fork_start.into();
        // At most one of these can be 1
        builder
            .when(is_chain_start.clone())
            .assert_bool(is_chain_start.clone());

        let next_is_chain_start: AB::Expr = next.is_proof_start.into() + next.is_fork_start.into();

        // proof_idx ordering via NestedForLoopSubAir<1>.
        NestedForLoopSubAir::<1> {}.eval(
            builder,
            (
                NestedForLoopIoCols {
                    is_enabled: is_valid,
                    counter: [local.proof_idx],
                    is_first: [local.is_proof_start],
                }
                .map_into(),
                NestedForLoopIoCols {
                    is_enabled: next_valid,
                    counter: [next.proof_idx],
                    is_first: [next.is_proof_start],
                }
                .map_into(),
            ),
        );

        // When is_proof_start: tidx = 0, sponge state = 0 (trunk start)
        builder.when(local.is_proof_start).assert_zero(local.tidx);
        builder.when(local.is_proof_start).assert_one(is_valid);
        builder
            .when(local.is_proof_start)
            .assert_zero(local.fork_id);
        builder.assert_bool(local.is_sample);

        // When is_fork_start: fork chain begins (tidx is NOT zero; it's the
        // fork's global tidx offset). Only constrain validity.
        builder.when(local.is_fork_start).assert_one(is_valid);

        // Initial state for proof start (trunk): all-zero sponge
        for i in 0..CHUNK {
            builder
                .when(local.is_proof_start)
                .assert_eq(local.prev_state[i + CHUNK], AB::Expr::ZERO);
            builder
                .when(local.is_proof_start * (AB::Expr::ONE - local.mask[i]))
                .assert_eq(local.prev_state[i], AB::Expr::ZERO);
        }

        ///////////////////////////////////////////////////////////////////////
        // Intra-chain continuity (sponge state propagation)
        ///////////////////////////////////////////////////////////////////////
        // Two consecutive rows are in the same chain iff next row is valid,
        // is not a proof start, and is not a fork start.
        let local_next_same_chain: AB::Expr = next_valid.into() - next_is_chain_start.clone();

        let mut count = AB::Expr::ZERO;
        for i in 0..CHUNK {
            builder.assert_bool(local.mask[i]);
            count += local.mask[i].into();

            let skip = local.mask[i] - AB::Expr::ONE;
            if i < CHUNK - 1 {
                builder.when(skip.clone()).assert_zero(local.mask[i + 1]);
            }

            // post_state -> next.prev_state continuity (rate positions)
            builder
                .when((AB::Expr::ONE - next.mask[i]) * local_next_same_chain.clone())
                .assert_eq(local.post_state[i], next.prev_state[i]);
            builder
                .when(next.is_sample * local_next_same_chain.clone())
                .assert_eq(local.post_state[i], next.prev_state[i]);

            // Capacity continuity
            builder
                .when(local_next_same_chain.clone())
                .assert_eq(local.post_state[i + CHUNK], next.prev_state[i + CHUNK]);
        }

        // tidx advances by count within the same chain
        builder
            .when(local_next_same_chain.clone())
            .assert_eq(next.tidx, local.tidx + count.clone());

        // If local.is_sample == next.is_sample within the same chain,
        // there must be exactly CHUNK operations.
        builder
            .when(local_next_same_chain.clone())
            .when_ne(local.is_sample, not(next.is_sample))
            .assert_eq(count, AB::Expr::from_usize(CHUNK));

        // fork_id continuity within same chain
        builder
            .when(local_next_same_chain.clone())
            .assert_eq(local.fork_id, next.fork_id);

        ///////////////////////////////////////////////////////////////////////
        // Transcript bus interactions (send)
        ///////////////////////////////////////////////////////////////////////
        for i in 0..CHUNK {
            let observe_message = TranscriptBusMessage {
                tidx: local.tidx + AB::Expr::from_usize(i),
                value: local.prev_state[i].into(),
                is_sample: AB::Expr::ZERO,
            };
            let sample_message = TranscriptBusMessage {
                tidx: local.tidx + AB::Expr::from_usize(i),
                value: local.prev_state[CHUNK - 1 - i].into(),
                is_sample: AB::Expr::ONE,
            };
            self.transcript_bus.send(
                builder,
                local.proof_idx,
                observe_message,
                local.mask[i] * (AB::Expr::ONE - local.is_sample),
            );
            self.transcript_bus.send(
                builder,
                local.proof_idx,
                sample_message,
                local.mask[i] * local.is_sample,
            );
        }

        ///////////////////////////////////////////////////////////////////////
        // Forked transcript bus interactions (send fork state)
        ///////////////////////////////////////////////////////////////////////
        // On is_fork_start rows, send fork-local transcript words with fork_id.
        for i in 0..D_EF {
            self.forked_transcript_bus.send(
                builder,
                local.proof_idx,
                ForkedTranscriptBusMessage {
                    fork_id: local.fork_id.into(),
                    tidx: local.tidx + AB::Expr::from_usize(i),
                    value: local.prev_state[i].into(),
                    is_sample: AB::Expr::ZERO,
                },
                local.is_fork_start,
            );
            self.forked_transcript_bus.send(
                builder,
                local.proof_idx,
                ForkedTranscriptBusMessage {
                    fork_id: local.fork_id.into(),
                    tidx: local.tidx + AB::Expr::from_usize(D_EF + i),
                    value: local.prev_state[i].into(),
                    is_sample: AB::Expr::ZERO,
                },
                local.is_fork_start,
            );
            self.forked_transcript_bus.send(
                builder,
                local.proof_idx,
                ForkedTranscriptBusMessage {
                    fork_id: local.fork_id.into(),
                    tidx: local.tidx + AB::Expr::from_usize(2 * D_EF + i),
                    value: local.prev_state[i].into(),
                    is_sample: AB::Expr::ONE,
                },
                local.is_fork_start,
            );
            self.forked_transcript_bus.send(
                builder,
                local.proof_idx,
                ForkedTranscriptBusMessage {
                    fork_id: local.fork_id.into(),
                    tidx: local.tidx + AB::Expr::from_usize(3 * D_EF + i),
                    value: local.prev_state[i].into(),
                    is_sample: AB::Expr::ONE,
                },
                local.is_fork_start,
            );
        }

        ///////////////////////////////////////////////////////////////////////
        // Poseidon2 permutation
        ///////////////////////////////////////////////////////////////////////
        let permuted = local_next_same_chain.clone()
            * not::<AB::Expr>(and(local.is_sample, not(next.is_sample)));
        self.poseidon2_permute_bus.lookup_key(
            builder,
            Poseidon2PermuteMessage {
                input: local.prev_state,
                output: local.post_state,
            },
            permuted.clone(),
        );

        assert_array_eq(
            &mut builder.when(not::<AB::Expr>(permuted)),
            local.prev_state,
            local.post_state,
        );

        ///////////////////////////////////////////////////////////////////////
        // Final state bus (optional)
        ///////////////////////////////////////////////////////////////////////
        if let Some(final_state_bus) = self.final_state_bus {
            final_state_bus.send(
                builder,
                local.proof_idx,
                FinalTranscriptStateMessage {
                    state: local.post_state,
                },
                and(is_valid, or(not(next_valid), next.is_proof_start)),
            );
        }
    }
}
