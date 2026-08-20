use ceno_gpu::common::witgen::types::DivColumnMap;
use ff_ext::ExtensionField;

use crate::instructions::{
    gpu::utils::column_map::{
        extract_rd, extract_rs1, extract_rs2, extract_state, extract_uint_limbs,
    },
    riscv::div::div_circuit_v2::DivRemConfig,
};

/// Extract column map from a constructed DivRemConfig.
/// div_kind: 0=DIV, 1=DIVU, 2=REM, 3=REMU
pub fn extract_div_column_map<E: ExtensionField>(
    config: &DivRemConfig<E>,
    num_witin: usize,
) -> DivColumnMap {
    let (pc, ts) = extract_state(&config.r_insn.vm_state);
    let (rs1_id, rs1_prev_ts, rs1_lt_diff) = extract_rs1(&config.r_insn.rs1);
    let (rs2_id, rs2_prev_ts, rs2_lt_diff) = extract_rs2(&config.r_insn.rs2);
    let (rd_id, rd_prev_ts, rd_prev_val, rd_lt_diff) = extract_rd(&config.r_insn.rd);

    let dividend = extract_uint_limbs::<E, 2, _, _>(&config.dividend, "dividend");
    let divisor = extract_uint_limbs::<E, 2, _, _>(&config.divisor, "divisor");
    let quotient = extract_uint_limbs::<E, 2, _, _>(&config.quotient, "quotient");
    let remainder = extract_uint_limbs::<E, 2, _, _>(&config.remainder, "remainder");

    // Sign/control bits
    let dividend_sign = config.dividend_sign.id as u32;
    let divisor_sign = config.divisor_sign.id as u32;
    let quotient_sign = config.quotient_sign.id as u32;
    let remainder_zero = config.remainder_zero.id as u32;
    let divisor_zero = config.divisor_zero.id as u32;

    // Inverse witnesses
    let divisor_sum_inv = config.divisor_sum_inv.id as u32;
    let remainder_sum_inv = config.remainder_sum_inv.id as u32;
    let remainder_inv: [u32; 2] = [
        config.remainder_inv[0].id as u32,
        config.remainder_inv[1].id as u32,
    ];

    // sign_xor
    let sign_xor = config.sign_xor.id as u32;

    let remainder_prime =
        extract_uint_limbs::<E, 2, _, _>(&config.remainder_prime, "remainder_prime");

    // lt_marker
    let lt_marker: [u32; 2] = [config.lt_marker[0].id as u32, config.lt_marker[1].id as u32];

    // lt_diff
    let lt_diff = config.lt_diff.id as u32;

    DivColumnMap {
        pc,
        ts,
        rs1_id,
        rs1_prev_ts,
        rs1_lt_diff,
        rs2_id,
        rs2_prev_ts,
        rs2_lt_diff,
        rd_id,
        rd_prev_ts,
        rd_prev_val,
        rd_lt_diff,
        dividend,
        divisor,
        quotient,
        remainder,
        dividend_sign,
        divisor_sign,
        quotient_sign,
        remainder_zero,
        divisor_zero,
        divisor_sum_inv,
        remainder_sum_inv,
        remainder_inv,
        sign_xor,
        remainder_prime,
        lt_marker,
        lt_diff,
        num_cols: num_witin as u32,
    }
}
