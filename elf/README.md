# Examples Builder

This crate allows easy embedding of example `elf` binaries into your code, usually for testing purposes.

Simply add `ceno-examples` to your dependencies, then reference the corresponding globals.

```toml
# Cargo.toml
# ...

[dev-dependencies]
ceno-elf = { path = "../elf" }
# ...
```

```rust
// foo.rs
let program_elf = ceno_elf::elf;
```
