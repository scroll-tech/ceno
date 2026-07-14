window.BENCHMARK_DATA = {
  "lastUpdate": 1784017284061,
  "repoUrl": "https://github.com/scroll-tech/ceno",
  "entries": {
    "GPU proving time": [
      {
        "commit": {
          "author": {
            "email": "xiakunxian130@gmail.com",
            "name": "xkx",
            "username": "kunxian-xia"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": false,
          "id": "def271c2840bcd859b1b82664d4f0c53ff8fdb06",
          "message": "Add recursion v2 aggregation with tower interleaving (#1363)\n\n## Problem\n\nThe existing recursion path does not cover the recursion-v2 verifier,\ntower interleaving, or jagged PCS proving path used by the current Ceno\nprover pipeline.\n\n## Design Rationale\n\nThe recursion verifier is represented as OpenVM recursion AIR with\nexplicit transcript, tower, main, PCS, proof-shape, and public-value\ncircuits. The design keeps native verifier data structures as the source\nof proof/vk semantics while making trace generation and GPU execution\nexplicit for maintainability and benchmark visibility.\n\n## Change Highlights\n\n- `ceno_recursion_v2`: add recursion-v2 AIR, trace generation,\npreflight, proof-shape, transcript, tower, main, PCS, root, and\ncontinuation prover modules.\n- `ceno_recursion_v2/cuda`: add CUDA tracegen kernels for tower, main,\nPCS, transcript, proof-shape, and frontload paths.\n- `ceno_zkvm`: add GPU proving updates for tower interleaving, jagged\nPCS, witness handling, and related circuit/gadget changes.\n- `ceno_cli`: expose recursion fan-in and recursion-v2 benchmark\ndefaults.\n- CI and docs: add recursion-v2 workflows, review guidance, and\nbenchmark-facing configuration.\n\n## Benchmark / Performance Impact\n\nBlock: `23817600`. Ratio is `baseline / this PR`; values above `1.0x`\nare faster in this PR.\n\n### Operation\n\n| Operation | baseline (s) | this PR (s) | Improve (baseline -> this PR)\n|\n\n|-----------|--------------|-------------|--------------------------------|\n| E2E elapsed | 143.000 | 78.700 | 1.82x |\n| app_prove | 66.400 | 57.400 | 1.16x |\n| commit_traces | 8.071 | 15.230 | 0.53x |\n| extract_witness_mles | 27.981 | 0.013 | 2152.38x |\n| transport_structural_witness | 2.668 | 5.151 | 0.52x |\n| build_tower_witness_gpu | 5.228 | 23.755 | 0.22x |\n| prove_tower_relation_gpu | 173.014 | 160.135 | 1.08x |\n| main constraints | 23.987 | 7.783 | 3.08x |\n| pcs_opening | 20.334 | 6.835 | 2.97x |\n\n### Layer\n\n| Layer | baseline (s) | this PR (s) | Improve (baseline -> this PR) |\n|-------|--------------|-------------|--------------------------------|\n| emulator | 10.300 | 10.200 | 1.01x |\n| app_prove | 66.400 | 57.400 | 1.16x |\n| recursion | 65.400 | 10.300 | 6.35x |\n| root_verify | N/A | 0.028 | N/A |\n| total reported layers | 142.100 | 77.900 | 1.82x |\n\nBenchmark command(s):\n\n```sh\nCENO_GPU_MEM_TRACKING=0 \\\nCENO_CONCURRENT_CHIP_PROVING=1 \\\nCENO_GPU_LARGE_TASK_BOOKING_MARGIN_MB=3048 \\\nCENO_GPU_ENABLE_WITGEN=0 \\\nCENO_MAX_CELL_PER_SHARD=1207959552 \\\nCENO_GPU_JAGGED_RESHAPE_LOG_HEIGHT=24 \\\nCENO_GPU_CACHE_LEVEL=1 \\\nRUSTFLAGS=\"-C target-feature=+avx2\" \\\ncargo run --features \"jemalloc,gpu\" --config net.git-fetch-with-cli=true -- \\\n  --mode prove-stark \\\n  --block-number 23817600 \\\n  --rpc-url '<redacted>' \\\n  --output-dir output \\\n  --cache-dir rpc-cache\n```\n\nEnvironment (CPU/GPU, core count, rust toolchain, commit hash):\n\n- CI runner from `ceno-reth-benchmark` workflow `Ceno Benchmark v2`.\n- GPU: CUDA runner with 24 GB device memory reported by the benchmark\nlog.\n- Rust: `cargo 1.93.0-nightly (2d4fa1395 2025-11-12)` for the\nrecursion-v2 run.\n- Baseline benchmark commit:\n`scroll-tech/ceno-reth-benchmark@9b747865d1c0c7cd43aa724e8aa8ae2becae1f7a`,\nCeno baseline from `feat/gpu-witness-gen`.\n- This PR benchmark commit:\n`scroll-tech/ceno-reth-benchmark@118520766b10af35f4395aa396bf6d59e6b2012b`,\nCeno `feat/recursion-v2` at `59f83f70daa95bc6c9001613e52c2f35a856007b`.\n\nraw data:\n\n- baseline:\nhttps://github.com/scroll-tech/ceno-reth-benchmark/actions/runs/24823660531,\nhttps://github.com/scroll-tech/ceno-reth-benchmark/blob/gh-pages/benchmarks-dispatch/refs/heads/feat/gpu-witness-gen/mainnet23817600-20260423-155553_summary.md\n- this PR:\nhttps://github.com/scroll-tech/ceno-reth-benchmark/actions/runs/29182745928,\nhttps://github.com/scroll-tech/ceno-reth-benchmark/blob/gh-pages/benchmarks-dispatch/refs/heads/feat/recursion-v2/mainnet23817600-20260712-143311_summary.md\n\n## Testing\n\n```sh\n# CI benchmark workflow succeeded for run 29182745928.\n# Baseline workflow succeeded for run 24823660531.\n```\n\n## Risks and Rollout\n\nThe main risks are verifier semantic drift between native and\nrecursion-v2 circuits, CUDA tracegen divergence from CPU trace\nconstruction, and benchmark sensitivity to CI runner hardware. Rollout\nshould keep native verifier checks and benchmark comparison available\nfor regression triage.\n\n## Follow-ups (optional)\n\n- Reduce remaining tower witness build time.\n- Keep root proof upload and trace-profiler metrics stable in benchmark\nCI.\n\n## Copilot Reviewer Directive (keep this section)\n\nWhen Copilot reviews this PR, apply `.github/copilot-instructions.md`\nstrictly.\n\n---------\n\nCo-authored-by: sm.wu <hero78119@gmail.com>\nCo-authored-by: Ray Gao <qg2153@columbia.edu>\nCo-authored-by: Claude Opus 4.6 <noreply@anthropic.com>",
          "timestamp": "2026-07-12T13:44:58Z",
          "tree_id": "4f3edceab293f1bd8233edcf50ffd286c71d04b3",
          "url": "https://github.com/scroll-tech/ceno/commit/def271c2840bcd859b1b82664d4f0c53ff8fdb06"
        },
        "date": 1783866018142,
        "tool": "customSmallerIsBetter",
        "benches": [
          {
            "name": "keccak_syscall proving time",
            "value": 0.722,
            "unit": "s"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "hero78119@gmail.com",
            "name": "Ming",
            "username": "hero78119"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "314db14cd9ed4c9d05e154578de93b215c3a4f8e",
          "message": "Introduce Ahead-of-time (AOT) to accelerate emulation (#1384)\n\n## Problem\n\nEmulation preflight is on the critical path for proving. It executes the\nguest program before witness generation to compute memory access\nmetadata, shard boundaries, cycle counts, and final memory state. The\ninterpreter is simple and exact, but its per-instruction dispatch\noverhead is visible on large blocks.\n\nThis PR introduces ahead-of-time (AOT) native execution as an emulator\nacceleration path, while keeping witness replay on the interpreter where\nexact `FullTracer` records are required.\n\n## Design Rationale\n\nAhead-of-time compilation is introduced at the emulator layer because\nthe emulator already owns instruction semantics, memory state, trap\nbehavior, and tracer updates. The AOT backend partitions statically\nreachable RISC-V basic blocks, lowers supported blocks into x86_64\nassembly, loads the generated shared object, and executes it against the\nexisting `VMState`. This keeps the optimization close to the interpreter\ninstead of duplicating semantics in the zkVM layer.\n\nThe design is intentionally hybrid. Native code is used for hot\nstraight-line instruction blocks where register arithmetic, branches,\nand simple memory accounting can avoid repeated interpreter dispatch.\nUnsupported instructions, syscalls, traps, dynamic control flow, guarded\nmemory cases, and other uncertain paths fall back to the original\ninterpreter. Dynamic block roots are sampled from a bounded preflight\ninterpreter pass so indirect targets that are not visible from static\ncontrol flow can still be compiled when they are hot.\n\nPreflight is the first consumer because it needs fast execution and\naggregate accounting, not exact witness records. The direct preflight\nAOT path updates `PreflightTracer` state from native execution,\nincluding access/cycle/cell accounting used for shard planning. This is\nwhere the measured win appears: on block 23817600, the emulator layer\nmoves from 10.200s to 6.550s, or 1.56x faster.\n\nWitness replay remains interpreter-backed. `FullTracer` replay is\nresponsible for exact step records, syscall witnesses, and shard-local\ntrace shape; changing that path would couple performance work to witness\ncorrectness. Keeping replay on the interpreter isolates AOT to preflight\nplanning and makes rollback straightforward.\n\nWith `aot-x86_64` enabled on Linux x86_64, AOT becomes the default\nemulator backend. `CENO_EMULATOR_BACKEND=interp` remains available for\nparity checks, debugging, and emergency rollback. No new runtime flag is\nadded.\n\nThe trade-off is explicit: this PR accelerates emulation preflight now,\nwhile deferring FullTracer AOT replay until record parity and\nshard-boundary parity can be proven independently.\n\n## Change Highlights\n\n- `ceno_zkvm`: replay uses interpreter-backed `StepReplay` for shard\nwitness generation.\n- `ceno_zkvm`: AOT/interpreter preflight parity coverage was added for\nshard planning.\n- `ceno_emul`: native preflight trace plumbing was kept explicit and\nclippy-clean.\n\n## Benchmark / Performance Impact\n\nBlock: mainnet 23817600. Baseline is `feat/recursion-v2`; this PR is\nbenchmark run 29304138526.\n\n### Layer\n\n| Layer | baseline (s) | this PR (s) | Change |\n|-------|--------------|-------------|--------|\n| emulator | 10.200 | 6.550 | 1.56x faster |\n| app_prove | 57.400 | 58.000 | noise |\n| recursion | 10.300 | 10.700 | noise |\n| total | 77.900 | 75.250 | 3.40% faster |\n\nBenchmark command(s):\n\n```sh\nceno-reth-benchmark workflow_dispatch, block 23817600, GPU enabled\n```\n\nEnvironment: GitHub benchmark runner, CUDA backend enabled,\n`CENO_MAX_CELL_PER_SHARD=1207959552`.\n\nraw data:\n\n- baseline:\nhttps://github.com/scroll-tech/ceno-reth-benchmark/blob/gh-pages/benchmarks-dispatch/refs/heads/feat/recursion-v2/mainnet23817600-20260712-143311_summary.md\n- this PR:\nhttps://github.com/scroll-tech/ceno-reth-benchmark/actions/runs/29304138526\n\n## Testing\n\n```sh\ncargo fmt --check\ncargo make clippy\ncargo test -p ceno_emul --features aot-x86_64 aot::tests -- --nocapture\ncargo check -p ceno_zkvm --features aot-x86_64\n```\n\n## Risks and Rollout\n\nThe main risk is AOT/interpreter shard-boundary drift in preflight\nplanning. Replay remains interpreter-backed to limit witness risk. If\nparity issues appear, the optimization can be rolled back by disabling\nAOT preflight selection.\n\n## Follow-ups (optional)\n\n- Prove and optimize FullTracer AOT replay separately before re-enabling\nit.\n- Fix any remaining native preflight accounting drift before relying on\nAOT shard boundaries.\n\n## Copilot Reviewer Directive (keep this section)\n\nWhen Copilot reviews this PR, apply `.github/copilot-instructions.md`\nstrictly.\n\n---------\n\nCo-authored-by: Ray Gao <qg2153@columbia.edu>\nCo-authored-by: kunxian xia <xiakunxian130@gmail.com>\nCo-authored-by: Claude Opus 4.6 <noreply@anthropic.com>",
          "timestamp": "2026-07-14T07:47:59Z",
          "tree_id": "3aae1ed401b5fbb9c948a8697bb3a4fb4ca93c13",
          "url": "https://github.com/scroll-tech/ceno/commit/314db14cd9ed4c9d05e154578de93b215c3a4f8e"
        },
        "date": 1784017283143,
        "tool": "customSmallerIsBetter",
        "benches": [
          {
            "name": "keccak_syscall proving time",
            "value": 0.705,
            "unit": "s"
          }
        ]
      }
    ]
  }
}