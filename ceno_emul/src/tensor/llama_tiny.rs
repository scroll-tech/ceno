//! Independent integer oracle for the complete `llama-tiny` layer profile.
//!
//! This module intentionally does not call the proving table generators. The
//! profile carries the nonlinear lookup outputs explicitly; every linear,
//! RoPE, residual, and fixed-point rescale step is recomputed here.

use anyhow::{Result, ensure};

pub const SEQUENCE: usize = 2;
pub const HIDDEN: usize = 2;
pub const HEADS: usize = 1;
pub const HEAD_DIM: usize = 2;
pub const INTERMEDIATE: usize = 2;
pub const Q16_SHIFT: u32 = 16;
pub const Q20_SHIFT: u32 = 20;
pub const SOFTMAX_SEGMENTS: usize = 5;

pub const INPUT: [[i32; HIDDEN]; SEQUENCE] = [[128, -64], [64, 128]];
pub const INPUT_NORM_WEIGHT: [i32; HIDDEN] = [8192, 6144];
pub const INPUT_INV_RMS: [i32; SEQUENCE] = [35_624_833, 35_624_833];
pub const Q_WEIGHT: [[i32; HIDDEN]; HIDDEN] = [[1, 1], [-1, 2]];
pub const K_WEIGHT: [[i32; HIDDEN]; HIDDEN] = [[1, -1], [1, 1]];
pub const V_WEIGHT: [[i32; HIDDEN]; HIDDEN] = [[1024, 256], [-128, 768]];
pub const ROPE_COS: [[i32; HEAD_DIM]; SEQUENCE] = [[63_516, 63_516], [57_510, 57_510]];
pub const ROPE_SIN: [[i32; HEAD_DIM]; SEQUENCE] = [[16_217, 16_217], [31_420, 31_420]];
pub const ATTENTION_SHIFTS: [i128; SEQUENCE] = [129_991_194, 18_085_893_153_580_672_258];
pub const SOFTMAX_DIGITS: [[[u16; SOFTMAX_SEGMENTS]; SEQUENCE]; SEQUENCE] = [
    [[50_656, 1_387, 0, 0, 0], [0, 0, 0, 0, 0]],
    [[957, 3_726, 0, 64_254, 0], [0, 0, 0, 64_254, 0]],
];
pub const SOFTMAX_PROBABILITIES: [[i32; SEQUENCE]; SEQUENCE] = [
    [1 << Q20_SHIFT, 0],
    [1 << (Q20_SHIFT - 1), 1 << (Q20_SHIFT - 1)],
];
pub const O_WEIGHT: [[i32; HIDDEN]; HIDDEN] = [[32_768, 8_192], [-4_096, 24_576]];
pub const POST_NORM_WEIGHT: [i32; HIDDEN] = [8192, 8192];
pub const POST_INV_RMS: [i32; SEQUENCE] = [27_030_305, 28_456_620];
pub const GATE_WEIGHT: [[i32; INTERMEDIATE]; HIDDEN] = [[2048, -1024], [512, 1536]];
pub const UP_WEIGHT: [[i32; INTERMEDIATE]; HIDDEN] = [[16_384, 4_096], [-2_048, 12_288]];
pub const SWIGLU_OUTPUT: [[i32; INTERMEDIATE]; SEQUENCE] = [[152, -112], [128, 56]];
pub const DOWN_WEIGHT: [[i32; HIDDEN]; INTERMEDIATE] = [[16_384, 2_048], [-4_096, 12_288]];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LlamaTinyLayerTrace {
    pub input_energy: [i32; SEQUENCE],
    pub input_norm: [[i32; HIDDEN]; SEQUENCE],
    pub q_projection: [[i32; HIDDEN]; SEQUENCE],
    pub k_projection: [[i32; HIDDEN]; SEQUENCE],
    pub v: [[i32; HIDDEN]; SEQUENCE],
    pub q_rope: [[i32; HIDDEN]; SEQUENCE],
    pub k_rope: [[i32; HIDDEN]; SEQUENCE],
    pub qk_scores: [[i64; SEQUENCE]; SEQUENCE],
    pub shifted_magnitudes: [[u128; SEQUENCE]; SEQUENCE],
    pub probabilities: [[i32; SEQUENCE]; SEQUENCE],
    pub attention: [[i32; HIDDEN]; SEQUENCE],
    pub attention_projection: [[i32; HIDDEN]; SEQUENCE],
    pub attention_residual: [[i32; HIDDEN]; SEQUENCE],
    pub post_energy: [i32; SEQUENCE],
    pub post_norm: [[i32; HIDDEN]; SEQUENCE],
    pub gate: [[i32; INTERMEDIATE]; SEQUENCE],
    pub up: [[i32; INTERMEDIATE]; SEQUENCE],
    pub swiglu: [[i32; INTERMEDIATE]; SEQUENCE],
    pub down_input: [[i32; INTERMEDIATE]; SEQUENCE],
    pub down: [[i32; HIDDEN]; SEQUENCE],
    pub output: [[i32; HIDDEN]; SEQUENCE],
}

fn centered_rescale(value: i64, shift: u32) -> Result<i32> {
    let half = 1i64 << (shift - 1);
    let quotient = value
        .checked_add(half)
        .ok_or_else(|| anyhow::anyhow!("rescale overflow"))?
        .div_euclid(1i64 << shift);
    Ok(i32::try_from(quotient)?)
}

fn matmul<const M: usize, const K: usize, const N: usize>(
    a: &[[i32; K]; M],
    w: &[[i32; N]; K],
    shift: Option<u32>,
) -> Result<[[i32; N]; M]> {
    let mut output = [[0; N]; M];
    for m in 0..M {
        for n in 0..N {
            let accum = (0..K).try_fold(0i64, |sum, k| {
                sum.checked_add(i64::from(a[m][k]) * i64::from(w[k][n]))
                    .ok_or_else(|| anyhow::anyhow!("matmul accumulator overflow"))
            })?;
            output[m][n] = match shift {
                Some(shift) => centered_rescale(accum, shift)?,
                None => i32::try_from(accum)?,
            };
        }
    }
    Ok(output)
}

fn rms_norm(
    input: &[[i32; HIDDEN]; SEQUENCE],
    inv: &[i32; SEQUENCE],
    weight: &[i32; HIDDEN],
) -> Result<[[i32; HIDDEN]; SEQUENCE]> {
    let mut output = [[0; HIDDEN]; SEQUENCE];
    for row in 0..SEQUENCE {
        for col in 0..HIDDEN {
            let weighted_inv =
                centered_rescale(i64::from(inv[row]) * i64::from(weight[col]), Q16_SHIFT)?;
            output[row][col] = centered_rescale(
                i64::from(weighted_inv) * i64::from(input[row][col]),
                Q16_SHIFT,
            )?;
        }
    }
    Ok(output)
}

fn energy(input: &[[i32; HIDDEN]; SEQUENCE]) -> Result<[i32; SEQUENCE]> {
    let mut output = [0; SEQUENCE];
    for row in 0..SEQUENCE {
        output[row] = i32::try_from(input[row].iter().try_fold(0i64, |sum, value| {
            sum.checked_add(i64::from(*value) * i64::from(*value))
                .ok_or_else(|| anyhow::anyhow!("RMS energy overflow"))
        })?)?;
    }
    Ok(output)
}

fn rope(values: &[[i32; HIDDEN]; SEQUENCE]) -> Result<[[i32; HIDDEN]; SEQUENCE]> {
    let mut output = [[0; HIDDEN]; SEQUENCE];
    for token in 0..SEQUENCE {
        output[token][0] = centered_rescale(
            i64::from(values[token][0]) * i64::from(ROPE_COS[token][0])
                - i64::from(values[token][1]) * i64::from(ROPE_SIN[token][0]),
            Q16_SHIFT,
        )?;
        output[token][1] = centered_rescale(
            i64::from(values[token][1]) * i64::from(ROPE_COS[token][1])
                + i64::from(values[token][0]) * i64::from(ROPE_SIN[token][1]),
            Q16_SHIFT,
        )?;
    }
    Ok(output)
}

fn add(
    left: &[[i32; HIDDEN]; SEQUENCE],
    right: &[[i32; HIDDEN]; SEQUENCE],
) -> Result<[[i32; HIDDEN]; SEQUENCE]> {
    let mut output = [[0; HIDDEN]; SEQUENCE];
    for row in 0..SEQUENCE {
        for col in 0..HIDDEN {
            output[row][col] = left[row][col]
                .checked_add(right[row][col])
                .ok_or_else(|| anyhow::anyhow!("residual overflow"))?;
        }
    }
    Ok(output)
}

pub fn execute() -> Result<LlamaTinyLayerTrace> {
    let input_energy = energy(&INPUT)?;
    let input_norm = rms_norm(&INPUT, &INPUT_INV_RMS, &INPUT_NORM_WEIGHT)?;
    let q_projection = matmul(&input_norm, &Q_WEIGHT, None)?;
    let k_projection = matmul(&input_norm, &K_WEIGHT, None)?;
    let v = matmul(&input_norm, &V_WEIGHT, Some(Q16_SHIFT))?;
    let q_rope = rope(&q_projection)?;
    let k_rope = rope(&k_projection)?;
    let mut qk_scores = [[0i64; SEQUENCE]; SEQUENCE];
    let mut shifted_magnitudes = [[0u128; SEQUENCE]; SEQUENCE];
    for query in 0..SEQUENCE {
        for key in 0..SEQUENCE {
            qk_scores[query][key] = (0..HEAD_DIM)
                .map(|dim| i64::from(q_rope[query][dim]) * i64::from(k_rope[key][dim]))
                .sum();
            let shifted = i128::from(qk_scores[query][key]) - ATTENTION_SHIFTS[query];
            ensure!(shifted <= 0, "attention shift does not upper-bound score");
            shifted_magnitudes[query][key] = shifted.unsigned_abs();
            let mut magnitude = shifted_magnitudes[query][key];
            for expected in SOFTMAX_DIGITS[query][key] {
                ensure!(
                    magnitude & 0xffff == u128::from(expected),
                    "softmax digit mismatch"
                );
                magnitude >>= 16;
            }
            ensure!(magnitude == 0, "softmax magnitude exceeds five digits");
        }
    }
    let probabilities = SOFTMAX_PROBABILITIES;
    for query in 0..SEQUENCE {
        ensure!(
            probabilities[query]
                .iter()
                .map(|v| i64::from(*v))
                .sum::<i64>()
                == 1 << Q20_SHIFT,
            "softmax normalization mismatch"
        );
        ensure!(
            probabilities[query][query + 1..]
                .iter()
                .all(|value| *value == 0),
            "causal mask mismatch"
        );
    }
    let attention = matmul(&probabilities, &v, Some(Q20_SHIFT))?;
    let attention_projection = matmul(&attention, &O_WEIGHT, Some(Q16_SHIFT))?;
    let attention_residual = add(&INPUT, &attention_projection)?;
    let post_energy = energy(&attention_residual)?;
    let post_norm = rms_norm(&attention_residual, &POST_INV_RMS, &POST_NORM_WEIGHT)?;
    let gate = matmul(&post_norm, &GATE_WEIGHT, Some(Q20_SHIFT))?;
    let up = matmul(&post_norm, &UP_WEIGHT, Some(Q16_SHIFT))?;
    let swiglu = SWIGLU_OUTPUT;
    let mut down_input = [[0; INTERMEDIATE]; SEQUENCE];
    for row in 0..SEQUENCE {
        for col in 0..INTERMEDIATE {
            down_input[row][col] = centered_rescale(
                i64::from(swiglu[row][col]) * i64::from(up[row][col]),
                Q16_SHIFT,
            )?;
        }
    }
    let down = matmul(&down_input, &DOWN_WEIGHT, Some(Q16_SHIFT))?;
    let output = add(&attention_residual, &down)?;
    Ok(LlamaTinyLayerTrace {
        input_energy,
        input_norm,
        q_projection,
        k_projection,
        v,
        q_rope,
        k_rope,
        qk_scores,
        shifted_magnitudes,
        probabilities,
        attention,
        attention_projection,
        attention_residual,
        post_energy,
        post_norm,
        gate,
        up,
        swiglu,
        down_input,
        down,
        output,
    })
}

pub fn self_check() -> Result<()> {
    let trace = execute()?;
    ensure!(trace.input_energy == [20_480, 20_480], "input energy drift");
    ensure!(
        trace.input_norm == [[8_697, -3_262], [4_349, 6_523]],
        "input norm drift"
    );
    ensure!(
        trace.q_projection == [[11_959, 2_173], [-2_174, 17_395]],
        "Q drift"
    );
    ensure!(
        trace.k_projection == [[5_435, -11_959], [10_872, 2_174]],
        "K drift"
    );
    ensure!(trace.v == [[142, -4], [55, 93]], "V drift");
    ensure!(
        trace.q_rope == [[11_053, 5_065], [-10_247, 14_222]],
        "Q RoPE drift"
    );
    ensure!(
        trace.k_rope == [[8_227, -10_245], [8_498, 7_120]],
        "K RoPE drift"
    );
    ensure!(
        trace.qk_scores == [[39_042_106, 129_991_194], [-230_006_459, 14_181_634]],
        "QK drift"
    );
    ensure!(trace.attention == [[142, -4], [99, 45]], "P times V drift");
    ensure!(
        trace.attention_projection == [[71, 16], [47, 29]],
        "O drift"
    );
    ensure!(
        trace.attention_residual == [[199, -48], [111, 157]],
        "attention residual drift"
    );
    ensure!(trace.post_energy == [41_905, 36_970], "post energy drift");
    ensure!(
        trace.post_norm == [[10_260, -2_475], [6_025, 8_521]],
        "post norm drift"
    );
    ensure!(trace.gate == [[19, -14], [16, 7]], "gate drift");
    ensure!(trace.up == [[2_642, 177], [1_240, 1_974]], "up drift");
    ensure!(
        trace.down_input == [[6, 0], [2, 2]],
        "SwiGLU Hadamard drift"
    );
    ensure!(trace.down == [[2, 0], [0, 0]], "down drift");
    ensure!(
        trace.output == [[201, -48], [111, 157]],
        "layer output drift"
    );
    Ok(())
}
