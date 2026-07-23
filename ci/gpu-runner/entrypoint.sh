#!/usr/bin/env bash
# Entrypoint for the Ceno GPU self-hosted runner.
#
# Differs from the ceno-reth-benchmark reference entrypoint in one way: instead
# of taking a hard-coded RUNNER_TOKEN (which GitHub expires after ~1h and would
# make an auto-restart fail), start-runner.sh mints a FRESH registration token
# from the GitHub API on every start. The long-lived PAT stays on the host; this
# container receives only the short-lived registration token. That is what lets
# the cron watchdog restart this container indefinitely. It also runs an
# EPHEMERAL runner (exits cleanly after one job) so no state leaks between CI
# runs.
#
# Required env:
#   REPO_URL     - e.g. https://github.com/scroll-tech/ceno
# Optional env:
#   RUNNER_NAME  - defaults to gpu-<short-hostname>
#   RUNNER_LABELS- defaults to "self-hosted,Linux,X64,gpu"
set -euo pipefail

: "${REPO_URL:?set REPO_URL, e.g. https://github.com/scroll-tech/ceno}"

RUNNER_NAME="${RUNNER_NAME:-gpu-$(hostname | cut -c1-12)}"
RUNNER_LABELS="${RUNNER_LABELS:-self-hosted,Linux,X64,gpu}"
TOKEN_FILE="/run/runner-registration-token/token"
RUNNER_DIR="/home/docker/actions-runner"
cd "${RUNNER_DIR}"

if [[ ! -f "${TOKEN_FILE}" ]]; then
    echo "[entrypoint] ERROR: registration token file not found at ${TOKEN_FILE}" >&2
    exit 1
fi

REG_TOKEN="$(<"${TOKEN_FILE}")"
rm -f "${TOKEN_FILE}" || true

if [[ -z "${REG_TOKEN}" || "${REG_TOKEN}" == "null" ]]; then
    echo "[entrypoint] ERROR: registration token file was empty" >&2
    exit 1
fi

cleanup() {
    echo "[entrypoint] de-registering runner ..."
    ./config.sh remove --token "${REG_TOKEN}" || true
}
trap 'cleanup' EXIT INT TERM

# Fail fast if the GPU isn't actually reachable inside the container — otherwise
# an ephemeral runner would pick up a GPU job and fail it.
if command -v nvidia-smi >/dev/null 2>&1; then
    echo "[entrypoint] GPU check:"
    nvidia-smi -L || { echo "[entrypoint] ERROR: nvidia-smi failed; is --gpus set + toolkit installed?" >&2; exit 1; }
else
    echo "[entrypoint] WARNING: nvidia-smi not found in container" >&2
fi

echo "[entrypoint] configuring ephemeral runner '${RUNNER_NAME}' (labels: ${RUNNER_LABELS}) ..."
./config.sh \
    --url "${REPO_URL}" \
    --token "${REG_TOKEN}" \
    --name "${RUNNER_NAME}" \
    --labels "${RUNNER_LABELS}" \
    --work _work \
    --ephemeral \
    --unattended \
    --replace

echo "[entrypoint] starting runner ..."
exec ./run.sh
