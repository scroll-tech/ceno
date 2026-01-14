# Ceno Project Overview

Ceno is a non-uniform, segmentable, and parallelizable RISC-V Zero-Knowledge Virtual Machine (zkVM). It allows for the execution of Rust code in a verifiable manner, leveraging the power of zero-knowledge proofs.

## Key Features

- **RISC-V Architecture**: Ceno is built around the RISC-V instruction set, providing a standardized and open-source foundation for the virtual machine.
- **Zero-Knowledge Proofs**: The core of Ceno is its ability to generate zero-knowledge proofs of computation, ensuring that programs have been executed correctly without revealing any private inputs.
- **Rust Support**: Ceno is written in Rust and is designed to run programs also written in Rust, allowing developers to leverage the safety and performance of the Rust language.
- **Modularity**: The project is divided into several key components, each with a specific role in the Ceno ecosystem.

## Project Structure

The Ceno workspace is organized into the following main crates:

- `ceno_cli`: A command-line interface for interacting with the Ceno zkVM.
- `ceno_emul`: Provides emulation capabilities for the RISC-V instruction set.
- `ceno_host`: The host component responsible for managing the zkVM and orchestrating the proof generation process.
- `ceno_rt`: The runtime environment for guest programs running within the zkVM.
- `ceno_zkvm`: The core zkVM implementation, including the prover and verifier.
- `examples`: A collection of example programs that demonstrate how to use Ceno.
