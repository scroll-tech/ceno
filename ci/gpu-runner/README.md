# Ceno GPU self-hosted CI runner (Docker + cron auto-restart)

A GPU-capable, **ephemeral** GitHub Actions runner for this repo, packaged as a
Docker image and kept alive by a cron watchdog.

- **Ephemeral**: the runner exits cleanly after each job, so no state leaks
  between CI runs. The watchdog immediately brings up a fresh one.
- **Self-healing tokens**: the container mints a fresh registration token from
  the GitHub API on every start, so restarts never fail on an expired token.
- **Cron watchdog**: restarts the container if it stops *or* if the GPU becomes
  unreachable inside it (your stated failure mode).

## One-time host setup

The host must have an NVIDIA driver, Docker, and the **NVIDIA Container Toolkit**
(this is what makes `--gpus all` work):

```sh
# NVIDIA Container Toolkit (Ubuntu) — see NVIDIA docs for the current repo lines
curl -fsSL https://nvidia.github.io/libnvidia-container/gpgkey \
  | sudo gpg --dearmor -o /usr/share/keyrings/nvidia-container-toolkit-keyring.gpg
curl -s -L https://nvidia.github.io/libnvidia-container/stable/deb/nvidia-container-toolkit.list \
  | sed 's#deb https://#deb [signed-by=/usr/share/keyrings/nvidia-container-toolkit-keyring.gpg] https://#g' \
  | sudo tee /etc/apt/sources.list.d/nvidia-container-toolkit.list
sudo apt-get update && sudo apt-get install -y nvidia-container-toolkit
sudo nvidia-ctk runtime configure --runtime=docker
sudo systemctl restart docker

# sanity check: should print your GPU(s)
docker run --rm --gpus all nvidia/cuda:12.6.2-base-ubuntu24.04 nvidia-smi
```

Check the CUDA version your driver supports (top-right of `nvidia-smi`) and set
`CUDA_VERSION` in the Dockerfile / build arg to match (must be ≤ that).

## Private GPU backend: deploy key comes from GitHub secrets (not the image)

All cargo *git* deps pinned in `Cargo.toml` are **public** (`ceno-gpu-mock`,
`gkr-backend`, `ceno-patch`, `openvm`) and fetch over HTTPS with no auth. The
real GPU backend, however, is the **private `scroll-tech/ceno-gpu`** repo:
Cargo.toml's active `[patch]` redirects `ceno_gpu` away from the public
`ceno-gpu-mock` placeholder to the **local path `../ceno-gpu/cuda_hal`**. So a
`--features gpu` build needs `scroll-tech/ceno-gpu` cloned to `../ceno-gpu`
(a sibling of the checkout).

The runner **image carries no secrets**. The deploy key for `ceno-gpu` is stored
as a repo secret and loaded into an ssh-agent *inside each job*, which then
clones the repo to the path the patch expects.

Setup:
1. Add a **read-only deploy key** to the `scroll-tech/ceno-gpu` repo, and store
   the private half as a repo secret, e.g. `CENO_GPU_DEPLOY_KEY`.
2. In any GPU workflow, load it and clone `ceno-gpu` before the build:

```yaml
jobs:
  gpu-job:
    runs-on: [ self-hosted, Linux, X64, gpu ]
    steps:
      - uses: webfactory/ssh-agent@v0.9.0
        with:
          ssh-private-key: ${{ secrets.CENO_GPU_DEPLOY_KEY }}
      - uses: actions/checkout@v4
        with:
          lfs: true
      # the active [patch] expects ../ceno-gpu/cuda_hal to exist
      - run: git clone git@github.com:scroll-tech/ceno-gpu.git ../ceno-gpu
      - run: cargo build --release --features gpu
```

(`webfactory/ssh-agent` also adds github.com to known_hosts for the job.)

## Configure & first run

```sh
cp ci/gpu-runner/runner.env.example ci/gpu-runner/runner.env
$EDITOR ci/gpu-runner/runner.env     # paste PAT + repo URL

ci/gpu-runner/start-runner.sh
docker logs -f ceno-gpu-runner       # confirm it registered
```

To build manually:

```sh
docker build -t ceno-gpu-runner:latest -f ci/gpu-runner/Dockerfile .
```

In repo **Settings → Actions → Runners** you should now see a runner with the
`gpu` label. Point GPU jobs at it:

```yaml
runs-on: [ self-hosted, Linux, X64, gpu ]
```

(Non-GPU jobs keep using `[ self-hosted, Linux, X64 ]` and won't be scheduled
here because they don't request the `gpu` label.)

## Enable the cron watchdog

```sh
crontab -e
# add (use the ABSOLUTE path):
* * * * * /home/zbx/blockchain/ceno/ci/gpu-runner/watchdog.sh >> /var/log/ceno-gpu-runner.log 2>&1
```

The watchdog checks every minute and restarts on stop or GPU-unreachable.

## Files

| file                  | purpose                                                        |
|-----------------------|----------------------------------------------------------------|
| `Dockerfile`          | CUDA-devel image + actions runner + Rust toolchain + git-lfs   |
| `entrypoint.sh`       | mint token → configure ephemeral runner → run → de-register    |
| `start-runner.sh`     | (re)launch the container with `--gpus all`; idempotent         |
| `watchdog.sh`         | cron health check + restart                                    |
| `runner.env.example`  | template for `runner.env` (PAT + repo URL; gitignored)         |

## Notes & gotchas

- **PAT scope**: repo-level runner needs `repo` (classic) or fine-grained
  "Administration: Read and write" on this repo.
- **Warm builds across ephemeral restarts**: two named volumes persist between
  containers — `ceno-gpu-runner-cargo` (the cargo registry, so deps aren't
  re-downloaded) and `ceno-gpu-runner-target` (mounted at `/cache/target`, with
  `CARGO_TARGET_DIR` pointed at it so incremental compile artifacts survive).
  This keeps recompiles fast even though each job runs in a fresh container.
  Because of this, **GPU jobs can drop the `actions/cache` step for `target/`** —
  the host volume is bigger (no ~10 GB cache limit) and faster (no network
  restore) than GitHub's cache backend for a workspace this size. The single
  ephemeral runner serves one job at a time, so there's no concurrent writer on
  the shared target dir. (To reset: `docker volume rm ceno-gpu-runner-target`.)
- **Alternative to cron**: `--restart unless-stopped` in `start-runner.sh`
  restarts on crash instantly, but won't catch a hung container or a GPU that
  silently went away — that's why the watchdog also probes `nvidia-smi`.
- **Concurrency**: this is a single ephemeral runner = one job at a time. For N
  concurrent GPU jobs, run N containers (`CONTAINER_NAME=ceno-gpu-runner-2 …`)
  and one watchdog line each.
