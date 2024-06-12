benchmark
=======

rust benchmark powered by [criterion.rs](https://bheisler.github.io/criterion.rs/book/criterion_rs.html)

- [x] keccak256



### command
benchmark and save as `bashline`
```
cargo bench --bench <benchmark name> --features parallel --package gkr -- --save-baseline baseline
```

comparing with `baseline`
```
cargo bench --bench <benchmark name> --features parallel [--features <features to comparing with baseline> ...] --package gkr -- --baseline baseline
```

flamegraph
```
cargo bench --bench <benchmark name> --features parallel --features flamegraph --package gkr -- --profile-time <profile time in secs>
```
