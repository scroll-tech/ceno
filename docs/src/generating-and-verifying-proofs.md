# Generating and Verifying Proofs

The `cargo ceno` command provides a streamlined workflow for generating and verifying proofs of your ZK programs. This is handled primarily by the `prove` and `verify` subcommands.

## Proof Generation with `cargo ceno prove`

The `cargo ceno prove` command compiles, runs, and proves a Ceno guest program in one go. It takes the guest program's package as an argument and produces a proof file.

```bash
cargo ceno prove --package <GUEST_PACKAGE_NAME>
```

This command will:

1.  Compile the guest program into a RISC-V ELF file.
2.  Run the ELF file in the Ceno ZKVM.
3.  Generate a proof of the execution.
4.  Save the proof to a file, typically named `<GUEST_PACKAGE_NAME>.proof` in the `target/` directory.

You can also specify the output path for the proof file:

```bash
cargo ceno prove --package <GUEST_PACKAGE_NAME> --output <PATH_TO_PROOF_FILE>
```

## Verification with `cargo ceno verify`

Once you have a proof file, you can verify it using the `cargo ceno verify` command. This command takes the proof file as an argument and checks its validity.

```bash
cargo ceno verify <PATH_TO_PROOF_FILE>
```

If the proof is valid, the command will exit successfully. If the proof is invalid, it will report an error.

## The Proving Process in Detail

The `prove` command is a convenient wrapper around a multi-step process. Here's a more detailed look at the steps involved in generating a proof:

1.  **Key Generation (`cargo ceno keygen`):** Before proving, you need a proving key and a verification key. The `keygen` command generates these keys for a given guest program.

    ```bash
    cargo ceno keygen --package <GUEST_PACKAGE_NAME> --proving-key-path <PK_PATH> --verifying-key-path <VK_PATH>
    ```

2.  **Execution and Witness Generation (`cargo ceno run`):** The `run` command executes the program and generates a "witness", which is a record of the execution trace. This witness is then used in the proving step.

    ```bash
    cargo ceno run --package <GUEST_PACKAGE_NAME> --witness-path <WITNESS_PATH>
    ```

3.  **Proof Generation (using the witness):** The final step is to use the proving key and the witness to generate the proof. The `prove` command automates this, but you can also perform this step manually using the lower-level `raw-prove` command if you have the ELF file, proving key, and witness.

By using `cargo ceno prove`, you get a simplified experience that handles these steps for you. For most use cases, `cargo ceno prove` and `cargo ceno verify` are the primary commands you will use.
