window.BENCHMARK_DATA = {
  "lastUpdate": 1783866018963,
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
      }
    ]
  }
}