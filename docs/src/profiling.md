# Profiling & Performance

Ceno includes tools to help you analyze and optimize the performance of your ZK programs.

## Execution Profiling

You can profile the execution of your guest program by using the `--profiling` flag with the `ceno run` or other binary commands. This will output detailed statistics about the execution, such as cycle counts for different parts of the program.

For example:
```bash
ceno run --profiling=1 -- <your_program>
```

The value passed to `--profiling` controls the granularity of the profiling information.

The output will show a tree of spans with timing information, allowing you to identify performance bottlenecks in your code.

## Benchmarking

The `ceno_zkvm` crate contains a `benches` directory with several benchmarks. You can use these as a reference for writing your own benchmarks using `criterion`.

Running the benchmarks can give you an idea of the performance of different operations and help you optimize your code. To run the benchmarks, you can use the standard `cargo bench` command.
