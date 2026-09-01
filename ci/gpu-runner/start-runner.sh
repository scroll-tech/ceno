#!/usr/bin/env bash
# Build (if needed) and (re)start the GPU runner container.
# Idempotent: safe to call from the cron watchdog — it removes any stale
# container of the same name first.
set -euo pipefail

cd "$(dirname "$0")/../.."          # repo root = docker build context

RUNNER_DIR="ci/gpu-runner"
CONTAINER_NAME="${CONTAINER_NAME:-ceno-gpu-runner}"
IMAGE_NAME="${IMAGE_NAME:-ceno-gpu-runner:latest}"
ENV_FILE="${ENV_FILE:-$(pwd)/${RUNNER_DIR}/runner.env}"

if [[ ! -f "${ENV_FILE}" ]]; then
    echo "ERROR: ${ENV_FILE} not found. Copy runner.env.example -> runner.env and fill it in." >&2
    exit 1
fi

# Keep runner.env host-only. It contains the long-lived PAT used to mint a
# short-lived runner registration token; do not pass it to docker with --env-file.
# shellcheck source=/dev/null
source "${ENV_FILE}"

: "${GITHUB_PAT:?set GITHUB_PAT in ${ENV_FILE}}"
: "${REPO_URL:?set REPO_URL in ${ENV_FILE}}"

# Build the image if it's missing (first run / after a host reboot+prune).
# No secrets at build time — the SSH deploy key is injected per-job from GitHub
# secrets via ssh-agent in the workflow.
if ! docker image inspect "${IMAGE_NAME}" >/dev/null 2>&1; then
    echo "[start] building ${IMAGE_NAME} ..."
    docker build -t "${IMAGE_NAME}" -f "${RUNNER_DIR}/Dockerfile" .
fi

# Drop any previous instance (exited ephemeral runner, crashed container, etc.).
docker rm -f "${CONTAINER_NAME}" >/dev/null 2>&1 || true

REPO_PATH="$(echo "${REPO_URL}" | sed -E 's#https?://[^/]+/##; s#\.git$##')"
API="https://api.github.com/repos/${REPO_PATH}/actions/runners"
TOKEN_DIR="${RUNNER_TOKEN_DIR:-${TMPDIR:-/tmp}/${CONTAINER_NAME}-registration-token}"
TOKEN_FILE="${TOKEN_DIR}/token"

echo "[start] requesting registration token for ${REPO_PATH} ..."
REG_TOKEN="$(curl -fsSL -X POST \
    -H "Authorization: Bearer ${GITHUB_PAT}" \
    -H "Accept: application/vnd.github+json" \
    -H "X-GitHub-Api-Version: 2022-11-28" \
    "${API}/registration-token" | jq -er .token)"

rm -rf "${TOKEN_DIR}"
mkdir -p "${TOKEN_DIR}"
chmod 755 "${TOKEN_DIR}"
printf '%s' "${REG_TOKEN}" > "${TOKEN_FILE}"
chmod 644 "${TOKEN_FILE}"

echo "[start] launching ${CONTAINER_NAME} ..."
if ! docker run -d \
    --name "${CONTAINER_NAME}" \
    --gpus all \
    --restart no \
    -e REPO_URL="${REPO_URL}" \
    -e RUNNER_NAME="${RUNNER_NAME:-}" \
    -e RUNNER_LABELS="${RUNNER_LABELS:-self-hosted,Linux,X64,gpu}" \
    -e CARGO_TARGET_DIR=/cache/target \
    -v "${TOKEN_DIR}:/run/runner-registration-token:rw" \
    -v ceno-gpu-runner-cargo:/home/docker/.cargo/registry \
    -v ceno-gpu-runner-target:/cache/target \
    "${IMAGE_NAME}"; then
    rm -rf "${TOKEN_DIR}"
    exit 1
fi

echo "[start] done. logs: docker logs -f ${CONTAINER_NAME}"
