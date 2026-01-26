# `cargo ceno build`

The `cargo ceno build` command compiles a Ceno program. It is a wrapper around the standard `cargo build` command, but it automatically sets the correct target and rustflags for building Ceno programs.

## Usage

```bash
cargo ceno build [OPTIONS]
```

## Options

The `build` command accepts all the same options as `cargo build`. Some of the most common options are:

- `--example <NAME>`: Build a specific example.
- `--release`: Build in release mode.
- `--package <NAME>` or `-p <NAME>`: Specify which package to build.
- `--workspace`: Build all packages in the workspace.

For a full list of options, run `cargo ceno build --help`.
