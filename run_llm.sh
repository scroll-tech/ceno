#!/usr/bin/env bash
set -uo pipefail

usage() {
  cat <<'EOF'
Usage: ./run_llm.sh --heads 1|2|4|8 [--shard-id ID] [--preflight-only] [--dry-run]

Build and run the production Tensor VM full-layer E2E on an NVIDIA GPU.
--heads is required. When --shard-id is supplied, that shard's proof is
persisted and independently verified with the same frozen executable.

Environment overrides:
  CUDA_ARCH                         CUDA architecture (default: 89 for RTX 4090)
  CENO_GPU_CACHE_LEVEL              GPU cache level (default: 1 / Trace)
  CENO_MAX_CELLS_PER_SHARD          planner cap (defaults by head count)
  CENO_SHARD_RAM_DEVICE_BUDGET_BYTES  ShardRAM device budget (default: 15032385536)
  CENO_RUN_ROOT                     run directory parent (default: /tmp/ceno-llm-runs)
  CENO_BUILD_TARGET_DIR             reusable Cargo target directory (default: RUN_DIR/target)
EOF
}

heads=""
shard_id=""
preflight_only=0
dry_run=0
while (($#)); do
  case "$1" in
    --heads)
      (($# >= 2)) || { echo "error: --heads requires a value" >&2; usage >&2; exit 2; }
      heads=$2
      shift 2
      ;;
    --shard-id)
      (($# >= 2)) || { echo "error: --shard-id requires a value" >&2; usage >&2; exit 2; }
      shard_id=$2
      shift 2
      ;;
    --preflight-only)
      preflight_only=1
      shift
      ;;
    --dry-run)
      dry_run=1
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "error: unknown argument: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

case "$heads" in
  1|2|4|8) ;;
  "") echo "error: --heads is required" >&2; usage >&2; exit 2 ;;
  *) echo "error: --heads must be one of 1, 2, 4, or 8" >&2; exit 2 ;;
esac
if [[ -n "$shard_id" && ! "$shard_id" =~ ^[0-9]+$ ]]; then
  echo "error: --shard-id must be a non-negative integer" >&2
  exit 2
fi

command -v cargo >/dev/null || { echo "error: cargo not found" >&2; exit 127; }
command -v nvidia-smi >/dev/null || { echo "error: nvidia-smi not found" >&2; exit 127; }

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
feature="production-heads-$heads"
groups=$((32 / heads))
log_rows=$((22 + $(awk -v n="$heads" 'BEGIN { while (n > 1) { n /= 2; b++ } print b + 0 }')))
total_rows=$((heads * 4194304))
case "$heads" in
  1) default_max_cells=3000000000 ;;
  2) default_max_cells=6000000000 ;;
  4) default_max_cells=12000000000 ;;
  8) default_max_cells=24000000000 ;;
esac

cuda_arch=${CUDA_ARCH:-89}
cache_level=${CENO_GPU_CACHE_LEVEL:-1}
max_cells=${CENO_MAX_CELLS_PER_SHARD:-$default_max_cells}
shard_ram_budget=${CENO_SHARD_RAM_DEVICE_BUDGET_BYTES:-15032385536}
run_root=${CENO_RUN_ROOT:-/tmp/ceno-llm-runs}
run_dir="$run_root/n${heads}-$(date +%Y%m%d-%H%M%S)-$$"
target_dir=${CENO_BUILD_TARGET_DIR:-$run_dir/target}
tmp_dir="$run_dir/tmp"
mkdir -p "$run_dir" "$target_dir" "$tmp_dir"

binary_name=tensor_bus_production_full_layer_v2_gpu_e2e
build_binary="$target_dir/release/examples/$binary_name"
frozen_binary="$run_dir/$binary_name-n${heads}"
proof_path="$run_dir/shard-${shard_id:-all}.proof"
build_log="$run_dir/build.log"
preflight_log="$run_dir/preflight.log"
run_log="$run_dir/prove-and-verify.log"
verify_log="$run_dir/independent-verify.log"
sample_log="$run_dir/nvidia-200ms.csv"

build_cmd=(cargo build --release -p ceno_zkvm --example "$binary_name"
  --features "gpu,tensor-cuda,aot-x86_64,$feature")
common_env=(
  "CENO_GPU_CACHE_LEVEL=$cache_level"
  CENO_GPU_PROFILE_BOUNDARIES=1
  CENO_GPU_SUMCHECK_V2_TIMING=1
  CENO_GPU_TOWER_PROOF_TIMING=1
  "CENO_MAX_CELLS_PER_SHARD=$max_cells"
  CENO_PIPELINE_TIMING=1
  "CENO_SHARD_RAM_DEVICE_BUDGET_BYTES=$shard_ram_budget"
  CENO_TENSOR_CONTEXT_RAM_AUDIT=1
  CENO_TENSOR_SOFTMAX_LK_AUDIT=1
  RUST_LOG=info
)

echo "run_dir=$run_dir"
echo "configuration heads=$heads feature=$feature groups=$groups total_rows=$total_rows log_rows=$log_rows cuda_arch=$cuda_arch cache_level=$cache_level max_cells=$max_cells"
printf 'build command: CUDA_ARCH=%q CARGO_TARGET_DIR=%q TMPDIR=%q' "$cuda_arch" "$target_dir" "$tmp_dir"
printf ' %q' "${build_cmd[@]}"
printf '\n'
if ((dry_run)); then
  echo "dry-run: no build, preflight, proof, or sampler started"
  exit 0
fi

summarize() {
  local status=$1
  echo
  echo "===== parsed summary ====="
  echo "status=$status heads=$heads feature=$feature groups=$groups configured_rows=$total_rows configured_log_rows=$log_rows"
  echo "logs: build=$build_log preflight=$preflight_log run=$run_log verify=$verify_log sampler=$sample_log"
  echo "-- group and shard plan --"
  sed -n '/production PureAotPrepass passed:/p;/pipeline timing phase=preflight/p' "$preflight_log" 2>/dev/null | tail -n 8
  echo "-- logged fused/PV shape --"
  sed -n '/TensorAttentionQkShiftSoftmax.*\(num_instances\|log_rows\|columns\)/p;/TensorAttentionPv.*\(num_instances\|log_rows\|columns\)/p' "$run_log" 2>/dev/null | tail -n 20
  echo "-- major timings --"
  sed -n '/pipeline timing phase=/p;/pipeline timing shard=/p;/production full-layer GPU E2E verified:/p' "$run_log" 2>/dev/null | tail -n 30
  echo "-- proof verification --"
  sed -n '/verified:/p;/verification:/p;/result=Ok(true)/p;/InvalidProof/p' "$run_log" "$verify_log" 2>/dev/null | tail -n 20

  local pool_peak framebuffer_peak external_peak sampled_peak
  pool_peak=$(sed -n 's/.*pool_high_water=\([0-9.]*\)MB.*/\1/p' "$run_log" 2>/dev/null | sort -nr | head -n1)
  framebuffer_peak=$(sed -n 's/.*framebuffer_high_water=\([0-9.]*\)MB.*/\1/p' "$run_log" 2>/dev/null | sort -nr | head -n1)
  external_peak=$(awk 'match($0,/cuda_used_bytes=[0-9]+/) { v=substr($0,RSTART+16,RLENGTH-16); if (v>m) m=v } END { if (m) printf "%.2f MiB",m/1048576 }' "$run_log" 2>/dev/null)
  sampled_peak=$(awk -F, '{ gsub(/ /,"",$4); if ($4+0>m) m=$4+0 } END { if (m) printf "%d MiB",m }' "$sample_log" 2>/dev/null)
  echo "-- VRAM peaks --"
  echo "pool=${pool_peak:-not logged} MB framebuffer=${framebuffer_peak:-not logged} MB external=${external_peak:-not logged} sampled=${sampled_peak:-not sampled}"
  echo "-- scheduler/OOM diagnosis --"
  sed -n '/scheduler deadlock/Ip;/out of memory/Ip;/CUDA_ERROR/Ip;/OOM/Ip;/admitted=false/p;/shortfall/p;/insufficient/Ip' "$run_log" 2>/dev/null | tail -n 30
  echo "===== end summary ====="
}

set +e
(
  cd "$repo_root" &&
    env CUDA_ARCH="$cuda_arch" CARGO_TARGET_DIR="$target_dir" TMPDIR="$tmp_dir" \
      /usr/bin/time -v "${build_cmd[@]}"
) 2>&1 | tee "$build_log"
build_status=${PIPESTATUS[0]}
set +e
if ((build_status != 0)); then
  summarize "$build_status (build failed)"
  exit "$build_status"
fi
cp "$build_binary" "$frozen_binary"
chmod 0555 "$frozen_binary"
sha256sum "$frozen_binary" | tee "$run_dir/binary.sha256"

set +e
env "${common_env[@]}" CENO_PREFLIGHT_ONLY=1 \
  /usr/bin/time -v "$frozen_binary" 2>&1 | tee "$preflight_log"
preflight_status=${PIPESTATUS[0]}
set +e
if ((preflight_status != 0)); then
  summarize "$preflight_status (preflight failed; proof not started)"
  exit "$preflight_status"
fi
if ((preflight_only)); then
  summarize "0 (preflight-only success)"
  exit 0
fi

nvidia-smi --query-gpu=timestamp,index,name,memory.used,memory.total,utilization.gpu \
  --format=csv,noheader,nounits --loop-ms=200 >"$sample_log" &
sampler_pid=$!
stop_sampler() {
  if [[ -n "${sampler_pid:-}" ]]; then
    kill "$sampler_pid" 2>/dev/null || true
    wait "$sampler_pid" 2>/dev/null || true
    sampler_pid=""
  fi
}
trap stop_sampler EXIT
trap 'stop_sampler; exit 130' INT TERM

run_env=("${common_env[@]}")
if [[ -n "$shard_id" ]]; then
  run_env+=("CENO_TARGET_SHARD_ID=$shard_id" "CENO_TARGET_PROOF_PATH=$proof_path")
fi
set +e
env "${run_env[@]}" /usr/bin/time -v "$frozen_binary" 2>&1 | tee "$run_log"
run_status=${PIPESTATUS[0]}
set +e
stop_sampler

final_status=$run_status
if ((run_status == 0)) && [[ -n "$shard_id" ]]; then
  if [[ ! -s "$proof_path" ]]; then
    echo "error: successful target-shard run did not create $proof_path" | tee -a "$run_log"
    final_status=1
  else
    sha256sum "$proof_path" | tee "$run_dir/proof.sha256"
    set +e
    env CENO_VERIFY_TARGET_PROOF_PATH="$proof_path" RUST_LOG=info \
      /usr/bin/time -v "$frozen_binary" 2>&1 | tee "$verify_log"
    verify_status=${PIPESTATUS[0]}
    set +e
    ((verify_status == 0)) || final_status=$verify_status
  fi
fi

summarize "$final_status"
exit "$final_status"
