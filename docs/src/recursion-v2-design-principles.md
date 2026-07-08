# Recursion V2 Design Principles

This document is a working design wiki for `ceno_recursion_v2`. The goal is to bridge the gap between the native `ceno_zkvm` Rust verifier and the recursion-v2 AIR, trace, transcript, and bus-message style.

`ceno_recursion_v2` is still incomplete. Treat this document as the shared migration model for implementing verifier logic module by module.

## Core Mental Model

The native Rust verifier is an imperative program. It checks a proof by executing functions, loops, branches, transcript operations, and assertions.

recursion-v2 proves that the same verifier program was executed correctly, but encoded as:

- preflight-prepared rows
- fixed AIR columns
- local algebraic constraints
- bus-linked function parameters
- transcript rows proving Fiat-Shamir order
- `proof_idx`, `chip_idx`, `air_idx`, and round keys connecting the module network

The translation rule is:

```text
Rust verifier function call -> AIR rows + local constraints + bus messages
Rust verifier loop          -> repeated matrix rows
Rust verifier local value   -> column value
Rust verifier assertion     -> AIR constraint
Rust verifier transcript op -> transcript row + transcript bus connection
```

Rows are the execution trace. Columns are the verifier state. AIR constraints are the assertions. Bus messages are function calls. `TranscriptAir` is the global Fiat-Shamir machine.

## Preflight

Preflight is deterministic verifier replay and trace preparation.

Its purpose is to convert verifier inputs into structured records that can be filled into AIR matrices. Preflight is like preparing matrix data, but it is not trusted by itself. Values computed by preflight are witness data until AIR constraints and bus messages prove them correct.

Typical preflight input:

```text
RecursionProof
RecursionVk
public values
proof_idx / chip_idx / air_idx metadata
transcript initial state
circuit ordering and AIR ordering
shape metadata
```

Typical preflight output:

```text
proof-shape records
transcript records
tower records
main records
sumcheck records
opening records
public-value records
bus-message payload records
```

Good preflight logic:

- parse proof structure
- derive row counts and trace shapes
- replay transcript order
- derive transcript challenges
- convert native proof arrays into row-oriented records
- assign `proof_idx`, `chip_idx`, `air_idx`, `layer_idx`, `round_idx`, and `tidx`
- compute helper values that AIR will later constrain
- build records in exactly the order expected by AIR trace generation

Bad preflight logic:

- trusting verifier equality without an AIR constraint
- silently accepting invalid proof shape
- computing a value used by another module without a bus equality
- replaying transcript differently from the native verifier
- hiding replay recomputation inside trace generation
- using placeholders without explicit TODO ownership and shape constraints

The standing rule is:

```text
Preflight owns replay and record preparation.
AIR owns correctness.
Bus messages own cross-module equality.
```

Blob and trace generation should consume preflight replay records read-only. Avoid hidden replay recomputation after preflight.

## Matrix View

recursion-v2 is a collection of 2D matrices. Each module owns one or more AIR tables, for example:

```text
ProofShapeAir
TranscriptAir
TowerInputAir
TowerLayerAir
TowerSumcheckAir
MainAir
MainSumcheckAir
OpeningAir
PublicValuesAir
```

Each row is one verifier step. Each column is one fixed field needed to check that step.

A proof, chip, layer, or round usually appears as one or more rows tagged by identifiers:

```text
proof_idx
chip_idx
air_idx
layer_idx
round_idx
tidx
is_present
is_first
is_last
```

`proof_idx` should be treated as a global key across the whole module network. Most modules either carry it directly or send and receive it through bus messages.

One proof may expand into many rows:

- one row per chip
- one row per AIR
- one row per tower layer
- one row per sumcheck round
- one row per transcript absorb
- one row per opening query

All expanded rows should carry enough key material to reconnect them to the original proof.

## Module Boundaries

Native Rust verifier module boundaries are not always the right AIR boundaries. The Rust verifier is organized for imperative readability and reuse; recursion-v2 should be organized for fixed-column constraints, row expansion, transcript ordering, and bus connectivity.

When mirroring native verifier logic, do not assume that one Rust function must become one AIR. It is acceptable to introduce one or more new modules or AIRs when that better exposes repeated structure as fixed columns plus rows.

Good reasons to split or introduce an AIR:

- a repeated verifier subroutine can become a narrow row-oriented table
- a native function mixes unrelated transcript, shape, and algebraic checks
- a value is produced by one logical stage and consumed by several later stages
- a bus boundary makes function parameters and return values clearer
- separate shape, transcript, and semantic constraints become easier to audit

Bad reasons to split:

- creating a module for every small helper function
- adding a bus where a local column constraint is enough
- hiding one-off logic behind a new AIR without repeated structure
- copying another project's module boundary without checking Ceno verifier semantics

Design rule:

```text
Choose AIR boundaries for constraint clarity and row reuse.
Do not over-engineer one-off verifier logic into unnecessary modules.
```

## Repeated Logic Becomes Rows

In Rust verifier code, repeated structure appears as loops:

```rust
for proof in proofs {
    for chip in chips {
        for round in rounds {
            verify_round(...);
        }
    }
}
```

In recursion-v2, those repeated iterations become rows.

Loop variables become row identifiers:

```text
proof_idx
chip_idx
air_idx
layer_idx
round_idx
```

Loop-local values become columns:

```text
claim_in
claim_out
challenge
evals
alpha
eq_at_r
```

Branches become selector columns:

```text
is_present
is_first
is_last
is_padding
is_grouped_shape
```

This applies even when the logic has a fixed maximum length. If the structure repeats, it is usually cheaper and clearer to encode it row-wise instead of adding many columns. Columns increase AIR width globally; rows are often the natural representation for repeated verifier work.

Design rule:

```text
Repeated dynamic structure      -> rows
Repeated fixed-length structure -> usually rows if columns would grow too much
Small fixed tuple               -> columns
Cross-module value              -> bus message
```

## Function Calls Become Bus Messages

In the native Rust verifier, data moves through function calls:

```rust
let tower_result = verify_tower(...);
verify_main(tower_result.rt_main, claimed_sum, ...);
```

In recursion-v2, modules do not call each other directly. Instead:

```text
Tower module sends:
  proof_idx, chip_idx, rt_main, tower_claim

Main module receives:
  proof_idx, chip_idx, rt_main, tower_claim
```

A bus message is the AIR equivalent of function arguments and return values.

If two modules need the same value, that value must either:

- be linked by bus, or
- be independently recomputed from values already linked by bus

Preflight may fill the same value into two matrices, but equality only becomes proven when constrained locally or through a bus.

For each bus, ask:

```text
What uniquely identifies this verifier value?
```

Example keys:

```text
Transcript value: proof_idx + tidx
Tower-to-main value: proof_idx + chip_idx
Proof-shape value: proof_idx + air_idx
Tower layer value: proof_idx + chip_idx + layer_idx
Sumcheck round value: proof_idx + chip_idx + layer_idx + round_idx
```

Good bus keys prevent accidental matching between unrelated rows.

## Transcript Module

The transcript module is the clearest example of recursion-v2 style.

In the native Rust verifier, transcript logic is imperative:

```rust
transcript.append_field_element_ext(value);
let challenge = transcript.sample_vec(...);
```

In recursion-v2, transcript operations become rows in a transcript matrix.

The transcript module has fixed columns. Preflight fills many rows with absorb and sample events:

```text
proof_idx
tidx
op_type
absorbed_value
sampled_value
label
state_before
state_after
```

The respective verifier module also stores the value it believes was absorbed or sampled. Equality is enforced through transcript bus messages.

Example:

```text
TowerAir has an alpha challenge column.
TranscriptAir has a sampled alpha row.
The transcript bus proves proof_idx, tidx, and alpha are the same.
```

Transcript conversion rule:

```text
Rust transcript append -> local module value + TranscriptAir absorb row + transcript bus
Rust transcript sample -> local module challenge + TranscriptAir sample row + transcript bus
```

This prevents each module from inventing its own challenges. The transcript module proves global Fiat-Shamir ordering, while each verifier module proves that it used the sampled values in its equations.

`tidx` should be treated as the transcript program counter. Any module that observes or samples transcript values should make its `tidx` progression explicit and bus-linked.

## Shape vs Semantics

Preflight prepares both shape data and semantic witness data, but AIR must prove the important parts.

Shape data:

```text
number of proofs
number of chips
number of AIRs
number of tower specs
number of rounds
number of transcript words
which rows are present
which rows are padding
```

Semantic data:

```text
sumcheck transition equations
tower aggregation equations
lookup dummy multiplicity
main claimed sum
opening evaluations
transcript challenge usage
cross-module value equality
```

`ProofShapeAir` exists so shape is globally visible. Other modules should not guess shape independently if they need to agree.

Important rule:

```text
If the native verifier distinguishes two counts, recursion-v2 should also distinguish them.
```

For grouped tower changes, for example:

```text
raw read count      = cs.num_reads()
proof read count    = proof.r_out_evals.len(), usually 0 or 1
tower variable size = derived from raw read count
transcript span     = derived from proof read count
```

Collapsing these into one field creates bugs.

## VK-Derived Data Ownership

If a value, field, count, expression, or branch condition is derived from the child VK in the native Rust verifier, recursion-v2 should reflect that same ownership.

Do not turn VK-derived verifier data into unconstrained proof witness data just because it is convenient to fill into a matrix. The source of truth should remain the child VK or a value derived from the child VK and made visible through proof-shape or VK-related records.

Examples of VK-derived data:

```text
circuit ordering
AIR/chip metadata
raw read/write/lookup counts
rotation variables
rotation subgroup size
GKR circuit shape
number of public values
number of witin/fixed/structural columns
table expression counts
whether a circuit has ECC ops
```

recursion-v2 may copy VK-derived data into preflight records or AIR columns, but those values should be treated as VK metadata, not as prover-chosen proof data. If another module needs the value, expose it through an explicit shape/VK metadata path or bus message.

Rule of thumb:

```text
Native verifier derives from child VK -> recursion-v2 derives from child VK or constrained VK metadata.
Native verifier reads from proof      -> recursion-v2 reads from proof records.
Native verifier derives from transcript -> recursion-v2 derives through TranscriptAir and transcript bus.
```

This distinction matters when a value appears both in proof data and VK data. The AIR should constrain that they agree instead of silently trusting the proof copy.

## Native Verifier Mapping Checklist

When mirroring a native Rust verifier block into recursion-v2, inspect the verifier code and classify:

```text
inputs
local derived values
assertions
loops
branches
transcript operations
return values
cross-module dependencies
```

Then map them to:

```text
preflight record fields
AIR columns
AIR constraints
selector columns
transcript rows
bus messages
shape metadata
```

Practical translation table:

```text
Rust input parameter       -> record field or bus receive
Rust return value          -> bus send
Rust local variable        -> witness column
Rust assertion             -> AIR constraint
Rust loop                  -> repeated rows
Rust if/else               -> selector columns
Rust transcript append     -> TranscriptAir absorb row + transcript bus
Rust transcript sample     -> TranscriptAir sample row + transcript bus
Rust vector length         -> ProofShapeAir metadata
Rust index                 -> row key column
Rust function side effect  -> local constraints or bus message
```

## Extra AIR Constraint Checklist

Imperative verifier code and AIR code have different failure modes. A native Rust verifier can rely on control flow, types, vector lengths, indexing, and function call boundaries. AIR tables need explicit constraints for many of those facts.

When migrating a module, identify constraints that are extra in AIR even if they are implicit in Rust.

Common AIR-only constraints:

- booleanity of selector columns such as `is_present`, `is_first`, `is_last`, and branch flags
- row transition constraints for counters such as `round_idx`, `layer_idx`, `chip_idx`, and `tidx`
- padding-row constraints so inactive rows cannot carry meaningful claims
- first-row and last-row boundary constraints
- shape agreement between local row counts and `ProofShapeAir`
- bus key equality for cross-module values
- transcript order and challenge-use equality through transcript bus messages
- range or domain checks for indices, counts, and enum-like fields
- active/inactive masking of sumcheck and tower equations
- consistency between proof-derived fields and VK-derived metadata
- uniqueness or balance constraints where native code would use a single function call

For every native assertion, ask two questions:

```text
What algebraic equation proves the same fact?
What extra row/selector/bus constraints are needed because this is now a table?
```

Do not stop at copying the native equation. AIR also needs to prove that the equation is applied to the right row, with the right key, under the right selector, and with the right transcript challenge.

## OpenVM as Reference, Not Template

OpenVM recursion code can be useful design reference:

```text
../openvm/crates/recursion/src
```

Use it to study row-oriented layouts, bus patterns, transcript tables, proof-shape handling, and module organization. Do not blindly copy it.

Ceno recursion-v2 must be tuned to Ceno's native verifier semantics:

- Ceno proof and VK types
- Ceno transcript order
- Ceno tower, main, lookup, rotation, and ECC verifier logic
- Ceno shape metadata and chip ordering
- Ceno-specific grouped/dense tower behavior

Reference OpenVM for design ideas; mirror `ceno_zkvm` for correctness.

## Migration Workflow

For each native verifier migration task:

1. Identify the native verifier block and exact source lines.
2. Write down the verifier inputs, outputs, transcript operations, assertions, and loops.
3. Mark which values are proof-derived, VK-derived, transcript-derived, or locally derived.
4. Decide which values are local to one AIR and which cross module boundaries.
5. Choose AIR/module boundaries for fixed-column clarity and repeated row structure, not blindly from Rust function boundaries.
6. Add or update preflight records for deterministic replay data.
7. Fill matrix rows from preflight records.
8. Add local AIR constraints for native verifier assertions.
9. Add AIR-only constraints for selectors, padding, row transitions, key equality, and shape agreement.
10. Add bus sends and receives for function parameters, return values, shape metadata, VK-derived metadata, and transcript values.
11. Validate AIR order, trace order, row counts, and transcript order before chasing deeper semantic failures.

Preferred implementation discipline:

- keep diffs surgical
- mirror native verifier naming when practical
- preserve row ordering and transcript ordering exactly
- add shape checks before semantic constraints
- avoid broad refactors during migration
- tag placeholders with explicit TODO ownership

## Grouped Tower Case Study

The grouped tower verifier change is a useful example of why shape and semantics must be separated.

Native verifier now distinguishes:

```text
raw counts:
  cs.num_reads()
  cs.num_writes()
  cs.num_lks()

proof counts:
  proof.r_out_evals.len()
  proof.w_out_evals.len()
  proof.lk_out_evals.len()
```

Grouped proof shape accepts:

```text
r_out_evals.len()  == usize::from(num_reads > 0)
w_out_evals.len()  == usize::from(num_writes > 0)
lk_out_evals.len() == usize::from(num_lks > 0)
```

Dense proof shape accepts:

```text
r_out_evals.len()  == num_reads
w_out_evals.len()  == num_writes
lk_out_evals.len() == num_lks
```

The transcript span follows proof counts, because only proof out-evals are absorbed.

The grouped tower variable depth follows raw counts:

```text
num_var_with_rotation + ceil_log2(raw_count.next_power_of_two())
```

The main verifier consumes the tail of the grouped tower point:

```text
rt_main = rt_tower[rt_tower.len() - num_var_with_rotation..]
```

This is because grouped operation-index coordinates are extra tower coordinates, while main-GKR still uses only row and rotation coordinates.

The recursion-v2 migration implication:

- `ProofShapeAir` should expose proof counts where transcript/table shape needs proof counts.
- raw counts must remain available where tower depth or lookup padding needs raw operation counts.
- tower replay must classify grouped vs dense shape.
- main replay should use `main_out_evals` and explicit `claimed_sum`, not reconstruct main claims from terminal tower values.
- transcript buses must use the grouped absorption schedule.

## Placeholder Policy

Temporary placeholders are allowed only when they are:

- deterministic
- shape-correct
- locally constrained enough to avoid unrelated failures
- tagged with explicit TODO ownership

Use comments like:

```rust
// TODO(recursion-v2-migration): replace placeholder with native verifier replay value.
```

Do not allow placeholders to hide shape mismatches, transcript ordering mismatches, or bus key mismatches.

## Acceptance Criteria for a Migration Step

A migration step is healthy when:

- `airs()` order matches trace context order
- number of AIRs matches number of generated trace matrices
- row counts match proof shape
- transcript `tidx` progression matches native verifier order
- bus sends and receives balance with correct keys
- placeholders are explicit and shape-correct
- the first failing validation reason is known if semantic verification is incomplete

Use native verifier behavior as the source of truth. recursion-v2 should encode the same verifier logic in row-oriented AIR form, not invent a parallel verifier.
