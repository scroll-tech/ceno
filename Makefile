# Makefile for conditional GPU builds

.PHONY: enable-gpu disable-gpu clean help

help:
	@echo "Available targets:"
	@echo "  enable-gpu   - Switch to GPU mode (uses remote implementation, requires private repo access)"
	@echo "  disable-gpu  - Switch to CPU mode (uses local placeholder, default state)"
	@echo "  clean        - Clean build artifacts and reset to CPU mode"
	@echo ""
	@echo "Normal usage:"
	@echo "  cargo build                    # CPU build (default, no private repo fetch)"
	@echo "  make enable-gpu && cargo build # GPU build (requires private repo access)"

enable-gpu:
	@./build-scripts/conditional-patch.sh enable-gpu

disable-gpu:
	@./build-scripts/conditional-patch.sh disable-gpu

clean:
	@cargo clean
	@./build-scripts/conditional-patch.sh disable-gpu
	@echo "Cleaned build artifacts and reset to CPU mode"
