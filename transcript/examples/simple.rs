use goldilocks::{Goldilocks, GoldilocksExt2 as E};
use transcript::basic::Transcript;
use transcript::Challenge;
use ff_ext::ff::Field;

const LOG2_NUM_FANIN: usize = 1;

fn main() {
    let mut transcript = Transcript::new(b"riscv");
    println!("Transcript: {:?}", transcript.read_challenge());
    let initial_rt: Vec<E> = (0..LOG2_NUM_FANIN)
        .map(|_| transcript.get_and_append_challenge(b"product_sum").elements)
        .collect();
    println!("Init RT = {:?}", initial_rt);
    transcript.append_field_element_exts(&[
        E::new_from_base(&[Goldilocks(1), Goldilocks(2)]),
        E::new_from_base(&[Goldilocks(3), Goldilocks(4)])
    ]);
    let r_merge: Vec<E> = (0..LOG2_NUM_FANIN)
        .map(|_| transcript.get_and_append_challenge(b"merge").elements)
        .collect();
    let challenge = transcript.read_challenge();
    println!("Challenge: {:?}", challenge);
    println!("Challenge Inv: {:?}", challenge.elements.invert());
    println!("R Merge = {:?}", r_merge);
}
