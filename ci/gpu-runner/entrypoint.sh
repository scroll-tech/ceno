#!/usr/bin/env bash
# Entrypoint for the Ceno GPU self-hosted runner.
#
# Differs from the ceno-reth-benchmark reference entrypoint in one way: instead
# of taking a hard-coded RUNNER_TOKEN (which GitHub expires after ~1h and would
# make an auto-restart fail), it mints a FRESH registration token from the
# GitHub API on every start using a stored PAT. That is what lets the cron
# watchdog restart this container indefinitely. It also runs an EPHEMERAL runner
# (exits cleanly after one job) so no state leaks between CI runs.
#
# Required env:
#   GITHUB_PAT   - classic PAT with `repo` scope, or fine-grained token with
#                  "Administration: read/write" on the repo. Used only to mint a
#                  runner registration token, then removed from the job env.
#   REPO_URL     - e.g. https://github.com/scroll-tech/ceno
# Optional env:
#   RUNNER_NAME  - defaults to gpu-<short-hostname>
#   RUNNER_LABELS- defaults to "self-hosted,Linux,X64,gpu"
set -euo pipefail

: "${GITHUB_PAT:?set GITHUB_PAT}"
: "${REPO_URL:?set REPO_URL, e.g. https://github.com/scroll-tech/ceno}"

RUNNER_NAME="${RUNNER_NAME:-gpu-$(hostname | cut -c1-12)}"
RUNNER_LABELS="${RUNNER_LABELS:-self-hosted,Linux,X64,gpu}"
RUNNER_DIR="/home/docker/actions-runner"
cd "${RUNNER_DIR}"

# REPO_URL -> owner/repo
REPO_PATH="$(echo "${REPO_URL}" | sed -E 's#https?://[^/]+/##; s#\.git$##')"
API="https://api.github.com/repos/${REPO_PATH}/actions/runners"

echo "[entrypoint] requesting registration token for ${REPO_PATH} ..."
REG_TOKEN="$(curl -fsSL -X POST \
    -H "Authorization: Bearer ${GITHUB_PAT}" \
    -H "Accept: application/vnd.github+json" \
    -H "X-GitHub-Api-Version: 2022-11-28" \
    "${API}/registration-token" | jq -r .token)"

if [[ -z "${REG_TOKEN}" || "${REG_TOKEN}" == "null" ]]; then
    echo "[entrypoint] ERROR: could not obtain registration token (check PAT scope/REPO_URL)" >&2
    exit 1
fi

# Do not pass the long-lived PAT into the Actions runner or any job steps.
unset GITHUB_PAT

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
