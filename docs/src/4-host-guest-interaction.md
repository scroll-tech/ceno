# Host-Guest Interaction

A critical aspect of developing ZK applications is understanding how the "host" (the machine running the prover) and the "guest" (the ZK program running inside the vm) communicate with each other.

In Ceno, this communication happens in two main ways:
1.  **Private Inputs (Hints)**: The host can pass private data to the guest.
2.  **Public Inputs/Outputs (I/O)**: The guest can receive public data and commit to public outputs that the host can verify.

We saw both of these in the command used to run the Fibonacci example:

```sh
... --hints=10 --public-io=4191 ...
```

## Private Inputs (Hints)

Private inputs, which Ceno refers to as "hints," are data known only to the host and the guest. They are not revealed publicly and do not become part of the final proof. This is the primary way to provide secret inputs to your ZK program.

In the guest code, you use the `ceno_rt::read()` function to access this data.

**Guest Code:**
```rust
// Reads the private hint value provided by the host.
let log_n: &Archived<u32> = ceno_rt::read();
let log_n: u32 = log_n.into();
```

**Host Command:**
```sh
... --hints=10 ...
```

In this interaction, the value `10` is passed from the host to the guest. The guest program reads this value and uses it to determine how many Fibonacci iterations to perform. This input remains private.

## Public Inputs and Outputs

Public I/O is data that is known to both the host and the verifier. It is part of the public record and is used to ensure the ZK program is performing the correct computation on the correct public data.

In Ceno, the guest program can commit data to the public record using the `ceno_rt::commit()` function.

**Guest Code:**
```rust
// Commits the final result `b` to the public output.
ceno_rt::commit::<Archived<u32>, _>(&b);
```

**Host Command:**
```sh
... --public-io=4191 ...
```

Here, the guest calculates the final Fibonacci number and commits the result `b`. The Ceno host environment then checks that this committed value is equal to the value provided in the `--public-io` argument (`4191`). If they do not match, the proof will fail, indicating an incorrect computation or a different result than expected.

This mechanism is crucial for creating verifiable computations. You can use public I/O to:

- Provide public inputs that the program must use.
- Assert that the program produces a specific, known public output.
