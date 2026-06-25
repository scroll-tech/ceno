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

## GPU integration workflow

`.github/workflows/gpu-integration.yml` proves an example end-to-end on the GPU
prover (`--features gpu`) on this runner. It's opt-in (GPU time is scarce):

- **Manually** — Actions tab → *GPU Integration* → *Run workflow*. Optionally
  set the `example` input (default `keccak_syscall`).
- **On a PR** — add the `gpu-ci` label to a branch in this repository. Fork PRs
  are skipped because they must not execute code on self-hosted runners.
- **On push to master** — records the proving-time baseline (see below).

It loads `secrets.CENO_GPU_DEPLOY_KEY` into ssh-agent, clones the private
`ceno-gpu` backend to `../ceno-gpu` (the path the Cargo `[patch]` expects), then
runs the example single-shard and multi-shard.

### Proving-time regression guard

The single-shard step extracts the **proving time** — the `ZKVM_create_proof`
span (pure proof generation) from `--profiling 1` (a `tracing-forest` tree) —
and feeds it to
[`benchmark-action/github-action-benchmark`](https://github.com/benchmark-action/github-action-benchmark)
(`customSmallerIsBetter`). History is stored on the **`gh-pages`** branch:

- **master push** appends the new measurement (and renders a chart at the repo's
  GitHub Pages site).
- **PRs** compare their measurement against the latest baseline and **fail** if
  proving is **>10% slower** (`alert-threshold: 110%`, `fail-on-alert: true`),
  posting a comment on the PR.

The first master run seeds `gh-pages`; until then PR runs have nothing to
compare against and pass. The job needs `contents: write` (push to gh-pages) and
`pull-requests: write` (regression comment), granted in the workflow.

## Enable the cron watchdog

```sh
crontab -e
# add (replace /ABS/PATH with this checkout's absolute path):
* * * * * /ABS/PATH/ceno/ci/gpu-runner/watchdog.sh >> $HOME/ceno-gpu-runner.log 2>&1
```

The watchdog checks every minute and restarts on stop or GPU-unreachable.

> **Log to a path the cron user can write.** The example logs to `$HOME`. Do
> **not** use `/var/log/…` unless the user owning the crontab can write there —
> if the `>>` redirect can't open its target, cron aborts the line *before*
> `watchdog.sh` runs, so it silently never executes (the error is mailed to the
> user, e.g. `/var/mail/<user>`, not logged). To use `/var/log` anyway:
> `sudo touch /var/log/ceno-gpu-runner.log && sudo chown "$USER" /var/log/ceno-gpu-runner.log`.
>
> Also ensure the crontab user is in the `docker` group, or the watchdog can't
> reach the daemon.

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
  "Administration: Read and write" on this repo. The entrypoint uses the PAT
  only to mint a runner registration token, then unsets it before starting the
  Actions runner so job steps do not inherit it.
- **Warm builds across ephemeral restarts**: two named volumes persist between
  containers — `ceno-gpu-runner-cargo` (the cargo registry, so deps aren't
  re-downloaded) and `ceno-gpu-runner-target` (mounted at `/cache/target`, with
  `CARGO_TARGET_DIR` pointed at it so incremental compile artifacts survive).
  This keeps recompiles fast even though each job runs in a fresh container.
  Because of this, **GPU jobs can drop the `actions/cache` step for `target/`** —
  the host volume is bigger (no ~10 GB cache limit) and faster (no network
  restore) than GitHub's cache backend for a workspace this size. PR jobs
  override `CARGO_TARGET_DIR` to the ephemeral workspace target so they do not
  share the trusted persistent target dir. The single ephemeral runner serves
  one job at a time, so there's no concurrent writer on the shared target dir.
  (To reset: `docker volume rm ceno-gpu-runner-target`.)
- **Fork PRs**: any workflow that targets this runner must guard PR jobs with
  `github.event.pull_request.head.repo.full_name == github.repository`, or use a
  GitHub-hosted runner for fork code.
- **Alternative to cron**: `--restart unless-stopped` in `start-runner.sh`
  restarts on crash instantly, but won't catch a hung container or a GPU that
  silently went away — that's why the watchdog also probes `nvidia-smi`.
- **Concurrency**: this is a single ephemeral runner = one job at a time. For N
  concurrent GPU jobs, run N containers (`CONTAINER_NAME=ceno-gpu-runner-2 …`)
  and one watchdog line each.
