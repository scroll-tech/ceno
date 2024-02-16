#![allow(clippy::manual_memcpy)]
#![allow(clippy::needless_range_loop)]

use ark_std::rand::{
    rngs::{OsRng, StdRng},
    Rng, RngCore, SeedableRng,
};
use ff::Field;
use gkr::{
    structs::{Circuit, CircuitWitness, PointAndEval},
    utils::MultilinearExtensionFromVectors,
};
use goldilocks::{GoldilocksExt2, SmallField};
use itertools::{chain, izip, Itertools};
use simple_frontend::structs::CircuitBuilder;
use std::iter;
use transcript::Transcript;

const RHO: [u32; 24] = [
    1, 3, 6, 10, 15, 21, 28, 36, 45, 55, 2, 14, 27, 41, 56, 8, 25, 43, 62, 18, 39, 61, 20, 44,
];

const PI: [usize; 24] = [
    10, 7, 11, 17, 18, 3, 5, 16, 8, 21, 24, 4, 15, 23, 19, 13, 12, 2, 20, 14, 22, 9, 6, 1,
];

const ROUNDS: usize = 24;

const RC: [u64; ROUNDS] = [
    1u64,
    0x8082u64,
    0x800000000000808au64,
    0x8000000080008000u64,
    0x808bu64,
    0x80000001u64,
    0x8000000080008081u64,
    0x8000000000008009u64,
    0x8au64,
    0x88u64,
    0x80008009u64,
    0x8000000au64,
    0x8000808bu64,
    0x800000000000008bu64,
    0x8000000000008089u64,
    0x8000000000008003u64,
    0x8000000000008002u64,
    0x8000000000000080u64,
    0x800au64,
    0x800000008000000au64,
    0x8000000080008081u64,
    0x8000000000008080u64,
    0x80000001u64,
    0x8000000080008008u64,
];

/// Bits of a word in big-endianess
#[derive(Clone, Copy, PartialEq, Eq)]
struct Word([usize; 64]);

impl Default for Word {
    fn default() -> Self {
        Self([0; 64])
    }
}

impl Word {
    fn new<F: SmallField>(cb: &mut CircuitBuilder<F>) -> Self {
        Self(cb.create_cells(64).try_into().unwrap())
    }

    fn rotate_left(&self, mid: usize) -> Self {
        let mut word = *self;
        word.0.rotate_left(mid);
        word
    }
}

// out = lhs ^ rhs = lhs + rhs - 2 * lhs * rhs
fn xor<F: SmallField>(cb: &mut CircuitBuilder<F>, lhs: &Word, rhs: &Word) -> Word {
    let out = Word::new(cb);
    izip!(&out.0, &lhs.0, &rhs.0).for_each(|(out, lhs, rhs)| {
        cb.add(*out, *lhs, F::BaseField::ONE);
        cb.add(*out, *rhs, F::BaseField::ONE);
        cb.mul2(*out, *lhs, *rhs, -F::BaseField::ONE.double());
    });
    out
}

fn xors<'a, F: SmallField>(
    cb: &mut CircuitBuilder<F>,
    words: impl IntoIterator<Item = &'a Word>,
) -> Word {
    let mut words = words.into_iter();
    let first = words.next().unwrap();
    let second = words.next().unwrap();
    words.fold(xor(cb, first, second), |acc, item| xor(cb, &acc, item))
}

// out = !lhs & rhs
fn not_lhs_and_rhs<F: SmallField>(cb: &mut CircuitBuilder<F>, lhs: &Word, rhs: &Word) -> Word {
    let out = Word::new(cb);
    izip!(&out.0, &lhs.0, &rhs.0).for_each(|(out, lhs, rhs)| {
        cb.add(*out, *rhs, F::BaseField::ONE);
        cb.mul2(*out, *lhs, *rhs, -F::BaseField::ONE);
    });
    out
}

fn xor_constant<F: SmallField>(cb: &mut CircuitBuilder<F>, lhs: &Word, constant: u64) -> Word {
    let mut out = *lhs;
    izip!(&mut out.0, (0..64).rev()).for_each(|(out, idx)| {
        if (constant >> idx) & 1 == 1 {
            let not = cb.create_cell();
            cb.add(not, *out, -F::BaseField::ONE);
            cb.add_const(not, F::BaseField::ONE);
            *out = not;
        }
    });
    out
}

// TODO: Optimization:
//       - Use mul3 to xor 3 thing at once to make Theta less layers, or use lookup
//       - Use mul3 to make Chi less layers
//       - Merge Iota into Chi
fn keccak256_circuit<F: SmallField>() -> Circuit<F> {
    let cb = &mut CircuitBuilder::new();

    let [mut state, input] = [25 * 64, 17 * 64].map(|n| {
        cb.create_wire_in(n)
            .1
            .chunks(64)
            .map(|word| Word(word.to_vec().try_into().unwrap()))
            .collect_vec()
    });

    // Absorption
    state = chain![
        izip!(&state, &input).map(|(state, input)| xor(cb, state, input)),
        state.iter().skip(input.len()).copied()
    ]
    .collect_vec();

    // Permutation
    for i in 0..ROUNDS {
        // Theta
        //
        // let mut array: [u64; 5] = [0; 5];
        // for x in 0..5 {
        //     for y_count in 0..5 {
        //         let y = y_count * 5;
        //         array[x] ^= state[x + y];
        //     }
        // }
        //
        // for x in 0..5 {
        //     for y_count in 0..5 {
        //         let y = y_count * 5;
        //         state[y + x] ^= array[(x + 4) % 5] ^ array[(x + 1) % 5].rotate_left(1);
        //     }
        // }

        let mut array = [Word::default(); 5];
        for x in 0..5 {
            for y_count in 0..5 {
                let y = y_count * 5;
                if array[x] == Word::default() {
                    array[x] = state[x + y];
                } else {
                    array[x] = xor(cb, &array[x], &state[x + y]);
                }
            }
        }

        for x in 0..5 {
            for y_count in 0..5 {
                let y = y_count * 5;
                state[y + x] = xors(
                    cb,
                    [
                        &state[y + x],
                        &array[(x + 4) % 5],
                        &array[(x + 1) % 5].rotate_left(1),
                    ],
                );
            }
        }

        // Rho and pi
        //
        // let mut last = state[1];

        // for x in 0..24 {
        //     array[0] = state[PI[x]];
        //     state[PI[x]] = last.rotate_left(RHO[x]);
        //     last = array[0];
        // }

        let mut last = state[1];

        for x in 0..24 {
            array[0] = state[PI[x]];
            state[PI[x]] = last.rotate_left(RHO[x] as usize);
            last = array[0];
        }

        // Chi
        //
        // for y_step in 0..5 {
        //     let y = y_step * 5;

        //     for x in 0..5 {
        //         array[x] = state[y + x];
        //     }

        //     for x in 0..5 {
        //         state[y + x] = array[x] ^ ((!array[(x + 1) % 5]) & (array[(x + 2) % 5]));
        //     }
        // }

        for y_step in 0..5 {
            let y = y_step * 5;

            for x in 0..5 {
                array[x] = state[y + x];
            }

            for x in 0..5 {
                let tmp = not_lhs_and_rhs(cb, &array[(x + 1) % 5], &array[(x + 2) % 5]);
                state[y + x] = xor(cb, &array[x], &tmp);
            }
        }

        // Iota
        //
        // state[0] ^= $rc[i];

        state[0] = xor_constant(cb, &state[0], RC[i]);
    }

    // FIXME: If we use the `create_wire_out_from_cells`, the ordering of these cells in wire_out
    //        will be different, so it's duplicating cells to avoid that as a temporary solution.
    // cb.create_wire_out_from_cells(&state.iter().flat_map(|word| word.0).collect_vec());

    let (_, out) = cb.create_wire_out(256);
    izip!(&out, state.iter().flat_map(|word| &word.0))
        .for_each(|(out, state)| cb.add(*out, *state, F::BaseField::ONE));

    cb.configure();
    Circuit::new(cb)
}

fn prove_keccak256<F: SmallField>(instance_num_vars: usize) {
    let circuit = keccak256_circuit::<F>();

    // Sanity-check
    {
        let all_zero = [
            vec![F::BaseField::ZERO; 25 * 64],
            vec![F::BaseField::ZERO; 17 * 64],
        ];
        let all_one = [
            vec![F::BaseField::ONE; 25 * 64],
            vec![F::BaseField::ZERO; 17 * 64],
        ];
        let mut witness = CircuitWitness::new(&circuit, Vec::new());
        witness.add_instance(&circuit, &all_zero);
        witness.add_instance(&circuit, &all_one);

        izip!(&witness.wires_out_ref()[0], [[0; 25], [u64::MAX; 25]]).for_each(
            |(wire_out, state)| {
                let output = wire_out[..256]
                    .chunks_exact(64)
                    .map(|bits| {
                        bits.iter().fold(0, |acc, bit| {
                            (acc << 1) + (*bit == F::BaseField::ONE) as u64
                        })
                    })
                    .collect_vec();
                let expected = {
                    let mut state = state;
                    tiny_keccak::keccakf(&mut state);
                    state[0..4].to_vec()
                };
                assert_eq!(output, expected)
            },
        );
    }

    let mut rng = StdRng::seed_from_u64(OsRng.next_u64());
    let mut witness = CircuitWitness::new(&circuit, Vec::new());
    for _ in 0..1 << instance_num_vars {
        let [rand_state, rand_input] = [25 * 64, 17 * 64].map(|n| {
            iter::repeat_with(|| rng.gen_bool(0.5) as u64)
                .take(n)
                .map(F::BaseField::from)
                .collect_vec()
        });
        witness.add_instance(&circuit, &[rand_state, rand_input]);
    }

    let lo_num_vars = witness.wires_out_ref()[0][0]
        .len()
        .next_power_of_two()
        .ilog2() as usize;
    let output_mle = witness.wires_out_ref()[0]
        .as_slice()
        .mle(lo_num_vars, instance_num_vars);

    let mut prover_transcript = Transcript::<F>::new(b"test");
    let output_point = iter::repeat_with(|| {
        prover_transcript
            .get_and_append_challenge(b"output point")
            .elements
    })
    .take(output_mle.num_vars)
    .collect_vec();
    let output_eval = output_mle.evaluate(&output_point);

    let start = std::time::Instant::now();
    let _proof = gkr::structs::IOPProverState::prove_parallel(
        &circuit,
        &witness,
        &[],
        &[PointAndEval::new(output_point, output_eval)],
        &mut prover_transcript,
    );
    println!("{}: {:?}", 1 << instance_num_vars, start.elapsed());

    // let mut verifer_transcript = Transcript::<F>::new(b"test");
    // let output_point = iter::repeat_with(|| {
    //     verifer_transcript
    //         .get_and_append_challenge(b"output point")
    //         .elements
    // })
    // .take(output_mle.num_vars)
    // .collect_vec();
    // let _claim = gkr::structs::IOPVerifierState::verify_parallel(
    //     &circuit,
    //     &[],
    //     &[],
    //     &[(output_point, output_eval)],
    //     &proof,
    //     instance_num_vars,
    //     &mut verifer_transcript,
    // )
    // .unwrap();
}

fn main() {
    println!(
        "#layers: {}",
        keccak256_circuit::<GoldilocksExt2>().layers.len()
    );

    for log2_n in 1..12 {
        prove_keccak256::<GoldilocksExt2>(log2_n);
    }
}
