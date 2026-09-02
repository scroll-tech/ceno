# Iteration 187 plan — PCS digest D2H/H2D lifecycle

## Objective

Test the explicitly authorized memory workaround: move the approximately
2-GiB Basefold opening digest from device to host immediately before batched
main, release device storage, then restore it to device immediately before the
PCS opening consumes it. Preserve exact digest bytes, commitment root,
transcript order, PCS equations, and proof/verifier behavior. Measure transfer
and host-memory overhead and determine whether OOM merely moves to PCS.

## Scope and ownership

- Own only the GPU Basefold commitment/witness lifecycle and the narrow ceno
  prover call sites needed to introduce an explicit spill/restore guard. A
  small internal commitment-state representation change is authorized for
  this purpose; public PCS algorithms and proof interfaces remain unchanged.
- Do not change Jagged layout, PIOP, PCS algorithms/equations, transcript,
  TensorBus, RAM/custom records, guest ABI, cache semantics, or proof format.
  The internal host-backed/device-backed digest state is the sole exception.
- Host spill is limited to this digest buffer; no q', witness MLE, key, or
  arbitrary workspace spill. No eviction/rematerialization of proof data.
- Preserve all current PV/Softmax/QK/SR-A changes and unrelated dirty files.
- Do not commit or push in this experiment.

## Required lifecycle

1. Identify the exact `BasefoldCommitmentWithWitness` digest owner and all uses.
2. D2H-copy the full digest with a byte-count/hash check; drop only its device
   allocation before batched-main. Keep a host-owned exact byte buffer alive.
3. Run shard0 batched-main and record q', retained, pool/framebuffer, slab,
   D2H bytes/time, host RSS, and peak host memory.
4. After main workspace is released or at the existing PCS-opening boundary,
   allocate the exact digest size and H2D-copy it; verify hash/root equality.
5. Complete PCS opening, proof serialization, and independent Rust verification.
6. If shard0 passes, run the full production 33-shard layer and verify all
   proofs; otherwise do not run the full layer.

## Acceptance gates

- D2H and H2D byte counts equal the original digest length; digest hash,
  commitment root, transcript challenge order, and PCS evaluations match.
- Device allocation is absent during batched-main and restored before PCS use;
  no use-after-free or stale device pointer remains.
- Main slab allocation succeeds; if PCS H2D fails, report exact phase and
  available memory rather than masking it.
- Record base-proof time, transfer time separately, proof size, verifier time,
  q'/retained/slab/VRAM/RSS, and full-layer metrics if reached.
- Any source mutation must be surgical, reversible, and build with the current
  production features. Run at most one changed shard0 E2E; a second is allowed
  only for a genuine fixable lifecycle bug.

## Frozen boundaries and terminal result

No PIOP/Jagged/PCS algorithm or public proof flow may change; only the internal
digest lifetime/state representation changes. Do not lower safety reserve or
change pool policy. Write
`iteration-187-worker.md` and return PASS, CHANGES_REQUIRED, REPLAN_REQUIRED,
or ENV_BLOCKED with context usage. If the digest cannot be safely detached
without changing the PCS interface, return REPLAN_REQUIRED with evidence.
