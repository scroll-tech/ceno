#![allow(clippy::manual_memcpy)]
#![allow(clippy::needless_range_loop)]

use std::{
    fs::File,
    io::{BufRead, BufReader},
    time::Duration,
};

use criterion::*;

use ff::Field;
use gkr::{gadgets::keccak256::prove_keccak256, structs::Circuit};
use goldilocks::{GoldilocksExt2, SmallField};
use itertools::{izip, Itertools};
use simple_frontend::structs::{CellId, CircuitBuilder};

// cargo bench --bench keccak256 --features parallel --features flamegraph --package gkr -- --profile-time <secs>
cfg_if::cfg_if! {
  if #[cfg(feature = "flamegraph")] {
    criterion_group! {
      name = keccak256_expander;
      config = Criterion::default().warm_up_time(Duration::from_millis(3000)).with_profiler(pprof::criterion::PProfProfiler::new(100, pprof::criterion::Output::Flamegraph(None)));
      targets = bench_keccak256
    }
  } else {
    criterion_group! {
      name = keccak256_expander;
      config = Criterion::default().warm_up_time(Duration::from_millis(3000));
      targets = bench_keccak256
    }
  }
}

criterion_main!(keccak256_expander);

/// Bits of a word in big-endianess
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
struct Word([usize; 64]);

impl Default for Word {
    fn default() -> Self {
        Self([0; 64])
    }
}

pub fn keccak256_circuit_from_file<F: SmallField>(
    add_gate_file_path: &str,
    mul2_gate_file_path: &str,
) -> Circuit<F> {
    let cb = &mut CircuitBuilder::new();

    // create input
    let _ = [25 * 64, 17 * 64].map(|n| {
        cb.create_witness_in(n)
            .1
            .chunks(64)
            .map(|word| Word(word.to_vec().try_into().unwrap()))
            .collect_vec()
    });

    let [add_gate_file, mul2_gate_file] = [
        File::open(add_gate_file_path).unwrap(),
        File::open(mul2_gate_file_path).unwrap(),
    ]
    .map(BufReader::new);

    // read gate file reversely to build layers from input to output
    let (last_layer_cellid_start, num_cellid_in_last_layer) = add_gate_file
        .lines()
        .collect::<Result<Vec<_>, _>>()
        .unwrap()
        .into_iter()
        .rev()
        .zip_eq(
            mul2_gate_file
                .lines()
                .collect::<Result<Vec<_>, _>>()
                .unwrap()
                .into_iter()
                .rev(),
        )
        .enumerate()
        .fold(
            (0, cb.cells.len()),
            |(last_layer_cellid_start, last_layer_cellid_offset), (layer_id, (add, mul))| {
                let current_layer_cellid_start = last_layer_cellid_start + last_layer_cellid_offset;
                let (mul_raw_gates, add_raw_gates) = (
                    mul.trim().split(" ").collect_vec(),
                    add.trim().split(" ").collect_vec(),
                );
                let (max_cellid_in_current_layer, num_of_mul_gates, num_of_add_gates) = {
                    let mut max_cellid_in_current_layer = 0;
                    let mut mul_iter = mul_raw_gates.iter();
                    let mut add_iter = add_raw_gates.iter();
                    let num_of_mul_gates = mul_iter
                        .next()
                        .and_then(|token| token.parse::<usize>().ok())
                        .unwrap_or(0); // num of gates

                    let num_of_add_gates = add_iter
                        .next()
                        .and_then(|token| token.parse::<usize>().ok())
                        .unwrap_or(0); // num of gates

                    for _ in 0..num_of_mul_gates {
                        let _in0 = mul_iter.next();
                        let _in1 = mul_iter.next();
                        let out = mul_iter
                            .next()
                            .and_then(|token| token.parse::<usize>().ok())
                            .unwrap();
                        let _scalar = mul_iter.next();
                        max_cellid_in_current_layer = max_cellid_in_current_layer.max(out);
                    }

                    for _ in 0..num_of_add_gates {
                        let _in0 = add_iter.next();
                        let out = add_iter
                            .next()
                            .and_then(|token| token.parse::<usize>().ok())
                            .unwrap();
                        let _scalar = add_iter.next();
                        max_cellid_in_current_layer = max_cellid_in_current_layer.max(out);
                    }
                    (
                        max_cellid_in_current_layer,
                        num_of_mul_gates,
                        num_of_add_gates,
                    )
                };
                // cell id stat from 0
                // create out cellid in each layers
                let num_cellid_in_current_layer = max_cellid_in_current_layer + 1;
                (0..num_cellid_in_current_layer).for_each(|_| {
                    cb.create_cell();
                });
                println!(
                    "layer {} with num_var {}",
                    layer_id + 1,
                    num_cellid_in_current_layer
                );

                let mut mul_iter = mul_raw_gates.into_iter().skip(1);
                let mut add_iter = add_raw_gates.into_iter().skip(1);

                // parse mul gate
                for _ in 0..num_of_mul_gates {
                    let (in_0, in_1, out, scalar) = (
                        mul_iter
                            .next()
                            .and_then(|token| token.parse::<usize>().ok())
                            .unwrap(),
                        mul_iter
                            .next()
                            .and_then(|token| token.parse::<usize>().ok())
                            .unwrap(),
                        mul_iter
                            .next()
                            .and_then(|token| token.parse::<usize>().ok())
                            .unwrap(),
                        mul_iter
                            .next()
                            .and_then(|token| token.parse::<usize>().ok())
                            .unwrap(),
                    );
                    cb.mul2(
                        CellId::from(out + current_layer_cellid_start),
                        CellId::from(in_0 + last_layer_cellid_start),
                        CellId::from(in_1 + last_layer_cellid_start),
                        F::BaseField::from(scalar.try_into().unwrap()),
                    );
                }

                // parse add gate
                for _ in 0..num_of_add_gates {
                    let (in_0, out, scalar) = (
                        add_iter
                            .next()
                            .and_then(|token| token.parse::<usize>().ok())
                            .unwrap(),
                        add_iter
                            .next()
                            .and_then(|token| token.parse::<usize>().ok())
                            .unwrap(),
                        add_iter
                            .next()
                            .and_then(|token| token.parse::<usize>().ok())
                            .unwrap(),
                    );
                    cb.add(
                        CellId::from(out + current_layer_cellid_start),
                        CellId::from(in_0 + last_layer_cellid_start),
                        F::BaseField::from(scalar.try_into().unwrap()),
                    );
                }
                (current_layer_cellid_start, num_cellid_in_current_layer)
            },
        );

    let (_, out) = cb.create_witness_out(num_cellid_in_last_layer);

    izip!(&out, last_layer_cellid_start..num_cellid_in_last_layer).for_each(
        |(out_cell_id, last_layer_cell_id)| {
            cb.add(*out_cell_id, last_layer_cell_id, F::BaseField::ONE)
        },
    );

    cb.configure();
    Circuit::new(cb)
}

const NUM_SAMPLES: usize = 10;

fn bench_keccak256(c: &mut Criterion) {
    let circuit = keccak256_circuit_from_file::<GoldilocksExt2>(
        "ExtractedCircuitAdd.txt",
        "ExtractedCircuitMul.txt",
    );
    println!("#layers: {}", circuit.layers.len());

    // let Some((proof, output_mle)) = prove_keccak256::<GoldilocksExt2>(1, &circuit) else {
    //     return;
    // };
    // assert!(verify_keccak256(1, output_mle, proof, &circuit).is_ok());

    for log2_n in 1..6 {
        // expand more input size once runtime is acceptable
        let mut group = c.benchmark_group(format!("keccak256_log2_{}", log2_n));
        group.sample_size(NUM_SAMPLES);

        // Benchmark the proving time
        group.bench_function(
            BenchmarkId::new("prove_keccak256", format!("keccak256_log2_{}", log2_n)),
            |b| {
                b.iter(|| {
                    assert!(prove_keccak256::<GoldilocksExt2>(log2_n, &circuit).is_some());
                });
            },
        );

        group.finish();
    }
}
