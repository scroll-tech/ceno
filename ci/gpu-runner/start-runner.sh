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

# Build the image if it's missing (first run / after a host reboot+prune).
# No secrets at build time — the SSH deploy key is injected per-job from GitHub
# secrets via ssh-agent in the workflow.
if ! docker image inspect "${IMAGE_NAME}" >/dev/null 2>&1; then
    echo "[start] building ${IMAGE_NAME} ..."
    docker build -t "${IMAGE_NAME}" -f "${RUNNER_DIR}/Dockerfile" .
fi

# Drop any previous instance (exited ephemeral runner, crashed container, etc.).
docker rm -f "${CONTAINER_NAME}" >/dev/null 2>&1 || true

echo "[start] launching ${CONTAINER_NAME} ..."
docker run -d \
    --name "${CONTAINER_NAME}" \
    --gpus all \
    --env-file "${ENV_FILE}" \
    --restart no \
    -e CARGO_TARGET_DIR=/cache/target \
    -v ceno-gpu-runner-cargo:/home/docker/.cargo/registry \
    -v ceno-gpu-runner-target:/cache/target \
    "${IMAGE_NAME}"

echo "[start] done. logs: docker logs -f ${CONTAINER_NAME}"
