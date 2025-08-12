# GPU Build Configuration

This workspace supports conditional compilation for GPU features while avoiding private repository access when GPU is not needed.

## Usage

### CPU-only Build (Default, No Private Repo Access)
```bash
cargo build -p ceno_zkvm --no-default-features
# or simply:
cargo build
```
- ✅ **Default behavior** - just works with normal `cargo build`
- ✅ Uses local placeholder for `ceno_gpu`
- ✅ No network access to private repository
- ✅ Safe for environments without private repo credentials

### GPU-enabled Build (Requires Setup + Private Repo Access)
```bash
# 1. Switch to GPU mode (one-time setup)
make enable-gpu

# 2. Build with GPU features
cargo build -p ceno_zkvm -F gpu

# 3. Switch back to CPU mode when done
make disable-gpu
```
- ✅ Uses real `ceno_gpu` implementation from private repository
- ⚠️  Requires SSH access to `ssh://git@github.com/scroll-tech/ceno-gpu.git`
- ⚠️  Requires one-time setup to switch modes

## How It Works

1. **Workspace Dependency**: `ceno_gpu` is defined in root `Cargo.toml` workspace dependencies
2. **Default State**: Points to local placeholder `path = "utils/cuda_hal"`
3. **Child Crates**: Use `ceno_gpu = { workspace = true, optional = true }`
4. **CPU Build**: Uses the local placeholder, all GPU modules are feature-gated and not compiled
5. **GPU Build**: Script modifies root `Cargo.toml` to use `git = "ssh://git@github.com/scroll-tech/ceno-gpu.git"`
6. **Single Point of Control**: Only need to modify one file (root `Cargo.toml`)

## Manual Commands

If you prefer direct script usage:

```bash
# Switch to GPU mode
./build-scripts/conditional-patch.sh enable-gpu
cargo build -p ceno_zkvm -F gpu

# Switch to CPU mode (default)
./build-scripts/conditional-patch.sh disable-gpu
cargo build -p ceno_zkvm --no-default-features

# Clean up and reset to CPU mode
make clean
```

## Files Modified

- `Cargo.toml`: Added `ceno_gpu` workspace dependency (single point of control)
- `ceno_zkvm/Cargo.toml`: Uses `ceno_gpu = { workspace = true, optional = true }`
- `gkr_iop/Cargo.toml`: Uses `ceno_gpu = { workspace = true, optional = true }`
- `gkr_iop/src/lib.rs`: Added `#[cfg(feature = "gpu")]` to `pub mod gpu;`
- `gkr_iop/src/gkr/layer.rs`: Added `#[cfg(feature = "gpu")]` to `pub mod gpu;`
- `utils/cuda_hal/`: Local placeholder crate
- `build-scripts/conditional-patch.sh`: Script for switching workspace dependency
- `Makefile`: Convenience targets for common build scenarios
