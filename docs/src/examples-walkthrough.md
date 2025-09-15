# Walkthroughs of Examples

This chapter will contain detailed walkthroughs of selected examples from the `examples/` directory.

## Fibonacci

The `fibonacci` example computes the `n`-th Fibonacci number, where `n` is a power of 2. The purpose of this example is to show how to perform a simple computation within the zkVM.

### Guest Code

The guest program for the `fibonacci` example is located at `examples/examples/fibonacci.rs`.

```rust
{{#include ../../examples/examples/fibonacci.rs}}
```

The code reads an input `log_n` from the host, which is used to calculate `n = 1 << log_n`. It then iteratively computes the `n`-th Fibonacci number modulo 7919. Finally, it commits the result `b` back to the host.

Key things to note:

- `ceno_rt::read()`: Reads private input from the host.
- `ceno_rt::commit()`: Commits public output to the host.
- The computation is standard Rust code. The zkVM can execute most simple Rust operations.

## Is Prime

The `is_prime` example counts the number of prime numbers up to a given integer `n`. This example showcases a slightly more complex algorithm and control flow.

### Guest Code

The guest program for the `is_prime` example is located at `examples/examples/is_prime.rs`.

```rust
{{#include ../../examples/examples/is_prime.rs}}
```

The code reads an integer `n` from the host. It then iterates from 0 to `n`, checking if each number is prime using the `is_prime` helper function. The total count of prime numbers is accumulated in `cnt_primes`. The program doesn't explicitly output the result but performs a computation that can be proven.

Key things to note:

- The `is_prime` function uses a standard trial division method.
- The guest program can include helper functions and more complex logic.
- The `panic!()` macro is used to demonstrate that the program can terminate with an error if a certain condition is met (though in this specific case, the condition `cnt_primes > 1000 * 1000` is unlikely to be met with typical inputs, it shows the possibility).
- The program does not commit any public output.

These examples provide a basic understanding of how to write programs for the Ceno zkVM. You can explore more complex examples in the `examples/` directory to learn about other features like syscalls and host-guest interaction.
