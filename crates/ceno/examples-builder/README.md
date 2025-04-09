# Examples Builder

This crate allows easy embedding of example `elf` binaries into your code, usually for testing purposes.

Simply add `ceno-examples` to your dependencies, then reference the corresponding globals.

```toml
# Cargo.toml
# ...

[dev-dependencies]
ceno-examples = { path = "../examples-builder" }
# ...
```

```rust
// foo.rs
let program_elf = ceno_examples::ceno_rt_io;
```
