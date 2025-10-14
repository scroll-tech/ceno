// taken from openvm/crates/circuits/poseidon2-air/src/babybear.rs
use super::poseidon2::RoundConstants;
use lazy_static::lazy_static;
use p3::{babybear::BabyBear, field::FieldAlgebra};
use std::array::from_fn;
use zkhash::{
    ark_ff::PrimeField as _, fields::babybear::FpBabyBear as HorizenBabyBear,
    poseidon2::poseidon2_instance_babybear::RC16,
};

const BABY_BEAR_POSEIDON2_WIDTH: usize = 16;
const BABY_BEAR_POSEIDON2_HALF_FULL_ROUNDS: usize = 4;
const BABY_BEAR_POSEIDON2_PARTIAL_ROUNDS: usize = 13;

pub(crate) fn horizen_to_p3_babybear(horizen_babybear: HorizenBabyBear) -> BabyBear {
    BabyBear::from_canonical_u64(horizen_babybear.into_bigint().0[0])
}

pub(crate) fn horizen_round_consts() -> RoundConstants<
    BabyBear,
    BABY_BEAR_POSEIDON2_WIDTH,
    BABY_BEAR_POSEIDON2_HALF_FULL_ROUNDS,
    BABY_BEAR_POSEIDON2_PARTIAL_ROUNDS,
> {
    let p3_rc16: Vec<Vec<BabyBear>> = RC16
        .iter()
        .map(|round| {
            round
                .iter()
                .map(|babybear| horizen_to_p3_babybear(*babybear))
                .collect()
        })
        .collect();
    let p_end = BABY_BEAR_POSEIDON2_HALF_FULL_ROUNDS + BABY_BEAR_POSEIDON2_PARTIAL_ROUNDS;

    let beginning_full_round_constants: [[BabyBear; BABY_BEAR_POSEIDON2_WIDTH];
        BABY_BEAR_POSEIDON2_HALF_FULL_ROUNDS] = from_fn(|i| p3_rc16[i].clone().try_into().unwrap());
    let partial_round_constants: [BabyBear; BABY_BEAR_POSEIDON2_PARTIAL_ROUNDS] =
        from_fn(|i| p3_rc16[i + BABY_BEAR_POSEIDON2_HALF_FULL_ROUNDS][0]);
    let ending_full_round_constants: [[BabyBear; BABY_BEAR_POSEIDON2_WIDTH];
        BABY_BEAR_POSEIDON2_HALF_FULL_ROUNDS] =
        from_fn(|i| p3_rc16[i + p_end].clone().try_into().unwrap());

    RoundConstants {
        beginning_full_round_constants,
        partial_round_constants,
        ending_full_round_constants,
    }
}

lazy_static! {
    pub static ref BABYBEAR_BEGIN_EXT_CONSTS: [[BabyBear; BABY_BEAR_POSEIDON2_WIDTH]; BABY_BEAR_POSEIDON2_HALF_FULL_ROUNDS] =
        horizen_round_consts().beginning_full_round_constants;
    pub static ref BABYBEAR_PARTIAL_CONSTS: [BabyBear; BABY_BEAR_POSEIDON2_PARTIAL_ROUNDS] =
        horizen_round_consts().partial_round_constants;
    pub static ref BABYBEAR_END_EXT_CONSTS: [[BabyBear; BABY_BEAR_POSEIDON2_WIDTH]; BABY_BEAR_POSEIDON2_HALF_FULL_ROUNDS] =
        horizen_round_consts().ending_full_round_constants;
}
