#!/usr/bin/env bash
# Cron watchdog for the Ceno GPU runner.
#
# Run it every minute from cron. It restarts the container if:
#   - the container is not in `running` state (crashed, or an ephemeral runner
#     finished a job and exited), OR
#   - nvidia-smi inside the container fails (GPU became unreachable).
#
# Crontab line (run `crontab -e` as the host user that owns docker access):
#   * * * * * /ABS/PATH/ceno/ci/gpu-runner/watchdog.sh >> /var/log/ceno-gpu-runner.log 2>&1
set -uo pipefail

# Serialize watchdog runs with a non-blocking lock. The first startup triggers a
# long image build during which the container still doesn't exist, so without
# this the next cron ticks would race a second start-runner.sh. `flock -n` makes
# overlapping ticks exit immediately instead.
exec 9>/tmp/ceno-gpu-runner-watchdog.lock
if ! flock -n 9; then
    exit 0
fi

cd "$(dirname "$0")"
CONTAINER_NAME="${CONTAINER_NAME:-ceno-gpu-runner}"
TS() { date -u +"%Y-%m-%dT%H:%M:%SZ"; }

state="$(docker inspect -f '{{.State.Status}}' "${CONTAINER_NAME}" 2>/dev/null || echo "absent")"

if [[ "${state}" != "running" ]]; then
    echo "$(TS) watchdog: container state='${state}', restarting"
    ./start-runner.sh
    exit 0
fi

# Container is running — verify the GPU is still actually usable.
if ! docker exec "${CONTAINER_NAME}" nvidia-smi -L >/dev/null 2>&1; then
    echo "$(TS) watchdog: GPU unreachable inside container, restarting"
    ./start-runner.sh
    exit 0
fi

# Healthy — stay quiet (no log spam every minute).
exit 0
