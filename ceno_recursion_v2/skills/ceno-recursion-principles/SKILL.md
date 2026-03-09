---
name: ceno-recursion-principles
description: Refactoring playbook for the `ceno_recursion_v2` crate when integrating OpenVM recursion components (system, continuation, provers) with Ceno-specific ZKVM proofs and verifying keys. Use when tasks mention ceno_recursion_v2 recursion system/prover changes, replacing MultiStark VKs with ZKVM VKs, copying OpenVM modules, or touching `ceno_recursion_v2/src/system` and `continuation/*`.
---

# Ceno Recursion Principles

## Overview

This skill captures the standing orders for evolving `ceno_recursion_v2`: reuse upstream OpenVM crates whenever possible, only fork modules that must diverge (e.g., to handle Ceno’s ZKVM proofs), and keep ZKVM <> OpenVM bridge logic localized.

## Quick Triggers

Use this skill when:
- Modifying `ceno_recursion_v2/src/system` or `src/continuation/**`
- Replacing `Proof<SC>` inputs with `ZKVMProof<RecursionField, Basefold<…>>`
- Swapping child verifying keys from `MultiStarkVerifyingKey<SC>` to `ZKVMVerifyingKey`
- Copying/patching OpenVM modules (recursion/continuation) into the Ceno crate
- Adding tests that deserialize `./src/imported/proof.bin`

## Core Principles

1. **Minimal Divergence** – Keep local copies only for code directly touched by the refactor. Everything else should import from upstream crates (e.g., `continuations_v2`, `recursion_circuit`, `openvm_*`). Remove local duplicates once upstream can be used again.
2. **ZKVM Proof First** – New APIs accept `ZKVMProof<RecursionField, Basefold<RecursionField, BasefoldRSParams>>` instead of OpenVM `Proof<SC>`. Provide adapters (currently `unimplemented!()` or TODO stubs) that convert into OpenVM structures right before trace generation.
3. **Recursion VK Alias** – Replace `Arc<MultiStarkVerifyingKey<SC>>` with `Arc<ZKVMVerifyingKey<RecursionField, Basefold<RecursionField, BasefoldRSParams>>>` wherever the “child VK” travels (constructors, traits, agg prover logic). Introduce a local alias (e.g., `type RecursionVk = ZKVMVerifyingKey<…>`) to keep signatures readable.
4. **Trait Copy Rule** – Only fork upstream definitions when the child-VK type must change. For example, copy `VerifierTraceGen` locally (because it takes `MultiStarkVerifyingKey`), but keep using upstream `VerifierConfig`, `VerifierExternalData`, and `CachedTraceCtx` directly so we don’t duplicate logic unnecessarily.
5. **Comment, Don’t Delete** – When slicing out unused functionality (compression/root/deferral), comment or `unimplemented!()` the sections you can’t finish yet so the call graph remains visible.

## Workflow

### 1. Identify Needed Forks
- Search upstream `openvm/crates/recursion` + `continuations-v2` for `MultiStarkVerifyingKey`.
- For each reference used by our code paths (“inner” continuation only right now), copy the minimal module into `ceno_recursion_v2/src/system` (mirror the original file layout).
- Replace imports to point at the local versions before editing types.

### 2. Introduce Recursion VK Alias
- In `inner/mod.rs` (and any copied traits), add:
  ```rust
  type RecursionVk = ZKVMVerifyingKey<RecursionField, Basefold<RecursionField, BasefoldRSParams>>;
  ```
- Update struct fields, constructor args, and helper signatures to use `Arc<RecursionVk>`.
- Where OpenVM still needs a `MultiStarkVerifyingKey<SC>`, create helper methods like `fn as_openvm_vk(&self) -> Arc<MultiStarkVerifyingKey<SC>>` that currently `unimplemented!()` until the translation exists.

### 3. Keep Upstream for Everything Else
- Circuit/AIR definitions, tracegen impls, transcript modules, and GKR logic should stay imported from upstream crates unless the type change forces a local copy.
- When copying files, preserve module paths (e.g., `system/mod.rs`, `system/verifier.rs`) so future diffs with upstream stay manageable.

### 4. Testing & Proof Artifacts
- Unit/integration tests should load `Vec<ZKVMProof<…>>` from `./src/imported/proof.bin` (and `vk.bin` when needed) using `bincode::deserialize_from`.
- Use the concrete engine alias `type E = BinomialExtensionField<BabyBear, 4>` / `type Engine = BabyBearPoseidon2CpuEngine<DuplexSponge>`.
- Until the bridge is implemented, leave test bodies `#[ignore]` with `unimplemented!()` placeholders after deserialization.

### 5. Cargo Hygiene
- Whenever new upstream crates are referenced (e.g., `verify-stark`, `continuations_v2` modules), add them to `ceno_recursion_v2/Cargo.toml` with the `develop-v2.0.0-beta` branch pin.
- Run `cargo check -p ceno_recursion_v2` (since the crate is excluded from the root workspace) after each major type tweak.

## Reference Paths

- Local system overrides: `ceno_recursion_v2/src/system/**`
- Continuation prover overrides: `ceno_recursion_v2/src/continuation/prover/**`
- Upstream mirrors: `/home/wusm/.cargo/git/checkouts/openvm-*/ac85e71/crates/...`
- Serialized artifact expectations: `./src/imported/proof.bin`, `./src/imported/vk.bin`
