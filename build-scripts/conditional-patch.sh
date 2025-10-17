#!/bin/bash

# Script to switch between local placeholder and remote GPU implementation
# Usage: ./build-scripts/conditional-patch.sh [enable-gpu|disable-gpu]

WORKSPACE_CARGO="Cargo.toml"

# Workspace dependency declarations
LOCAL_DEP='ceno_gpu = { path = "utils/cuda_hal", package = "cuda_hal" }'
REMOTE_DEP='ceno_gpu = { git = "ssh://git@github.com/scroll-tech/ceno-gpu.git", package = "cuda_hal", branch = "dev/integrate-into-ceno-as-dep", default-features = false, features = \["bb31"\] }'

if [ "$1" = "enable-gpu" ]; then
    echo "Switching to GPU mode (using remote implementation)..."
    
    # Replace local path with remote git in workspace dependencies
    if [[ "$OSTYPE" == "darwin"* ]]; then
        # macOS sed
        sed -i '' "s|${LOCAL_DEP}|${REMOTE_DEP}|g" "$WORKSPACE_CARGO"
    else
        # Linux sed
        sed -i "s|${LOCAL_DEP}|${REMOTE_DEP}|g" "$WORKSPACE_CARGO"
    fi
    
    echo "✅ Switched to remote GPU implementation"
    echo "Now you can run: cargo build -p ceno_zkvm -F gpu"
    
elif [ "$1" = "disable-gpu" ]; then
    echo "Switching to CPU mode (using local placeholder)..."
    
    # Replace remote git with local path in workspace dependencies
    if [[ "$OSTYPE" == "darwin"* ]]; then
        # macOS sed
        sed -i '' "s|${REMOTE_DEP}|${LOCAL_DEP}|g" "$WORKSPACE_CARGO"
    else
        # Linux sed
        sed -i "s|${REMOTE_DEP}|${LOCAL_DEP}|g" "$WORKSPACE_CARGO"
    fi
    
    echo "✅ Switched to local placeholder implementation"
    echo "Now you can run: cargo build -p ceno_zkvm --no-default-features"
    
else
    echo "Usage: $0 [enable-gpu|disable-gpu]"
    echo "  enable-gpu   - Switch to remote GPU implementation (requires private repo access)"
    echo "  disable-gpu  - Switch to local placeholder (default, no private repo access)"
    exit 1
fi

echo "Done."
