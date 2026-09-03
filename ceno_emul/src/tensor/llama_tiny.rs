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
pub const ATTENTION_SHIFTS: [i128; SEQUENCE] = [18_085_893_153_580_672_258; SEQUENCE];
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
    pub layer: u32,
    pub input: [[i32; HIDDEN]; SEQUENCE],
    pub input_inv_rms: [i32; SEQUENCE],
    pub input_energy: [i32; SEQUENCE],
    pub input_norm: [[i32; HIDDEN]; SEQUENCE],
    pub q_projection: [[i32; HIDDEN]; SEQUENCE],
    pub k_projection: [[i32; HIDDEN]; SEQUENCE],
    pub v: [[i32; HIDDEN]; SEQUENCE],
    pub q_rope: [[i32; HIDDEN]; SEQUENCE],
    pub k_rope: [[i32; HIDDEN]; SEQUENCE],
    pub qk_scores: [[i64; SEQUENCE]; SEQUENCE],
    pub shifted_magnitudes: [[u128; SEQUENCE]; SEQUENCE],
    pub softmax_digits: [[[u16; SOFTMAX_SEGMENTS]; SEQUENCE]; SEQUENCE],
    pub probabilities: [[i32; SEQUENCE]; SEQUENCE],
    pub attention: [[i32; HIDDEN]; SEQUENCE],
    pub attention_projection: [[i32; HIDDEN]; SEQUENCE],
    pub attention_residual: [[i32; HIDDEN]; SEQUENCE],
    pub post_energy: [i32; SEQUENCE],
    pub post_inv_rms: [i32; SEQUENCE],
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
    execute_layer(0, INPUT)
}

pub fn layer_input(layer: u32) -> Result<[[i32; HIDDEN]; SEQUENCE]> {
    let mut input = INPUT;
    for ordinal in 0..layer {
        input = execute_layer(ordinal, input)?.output;
    }
    Ok(input)
}

fn rms_inv(energy: i32) -> i32 {
    ((Q16_SHIFT as f64).exp2().powi(2)
        / (f64::from(energy) / 2.0 + 1.0e-6 * (Q16_SHIFT as f64).exp2().powi(2)).sqrt()
        + 0.5) as i32
}

fn softmax_product(magnitude: u128) -> i64 {
    let digit3 = ((magnitude >> 48) & 0xffff) as f64;
    let digit4 = ((magnitude >> 64) & 0xffff) as f64;
    let exp3 = (1024.0 * (-digit3 / (65_536.0 * 2.0f64.sqrt())).exp() + 0.5) as i64;
    let exp4 = (1024.0 * (-digit4 / 2.0f64.sqrt()).exp() + 0.5) as i64;
    1024_i64.pow(3) * exp3 * exp4
}

pub fn execute_layer(layer: u32, input: [[i32; HIDDEN]; SEQUENCE]) -> Result<LlamaTinyLayerTrace> {
    let input_energy = energy(&input)?;
    let input_inv_rms = input_energy.map(rms_inv);
    let input_norm = rms_norm(&input, &input_inv_rms, &INPUT_NORM_WEIGHT)?;
    let q_projection = matmul(&input_norm, &Q_WEIGHT, None)?;
    let k_projection = matmul(&input_norm, &K_WEIGHT, None)?;
    let v = matmul(&input_norm, &V_WEIGHT, Some(Q16_SHIFT))?;
    let q_rope = rope(&q_projection)?;
    let k_rope = rope(&k_projection)?;
    let mut qk_scores = [[0i64; SEQUENCE]; SEQUENCE];
    let mut shifted_magnitudes = [[0u128; SEQUENCE]; SEQUENCE];
    let mut softmax_digits = [[[0u16; SOFTMAX_SEGMENTS]; SEQUENCE]; SEQUENCE];
    for query in 0..SEQUENCE {
        for key in 0..SEQUENCE {
            qk_scores[query][key] = (0..HEAD_DIM)
                .map(|dim| i64::from(q_rope[query][dim]) * i64::from(k_rope[key][dim]))
                .sum();
            let shifted = i128::from(qk_scores[query][key]) - ATTENTION_SHIFTS[query];
            ensure!(shifted <= 0, "attention shift does not upper-bound score");
            shifted_magnitudes[query][key] = shifted.unsigned_abs();
            let mut magnitude = shifted_magnitudes[query][key];
            for digit in &mut softmax_digits[query][key] {
                *digit = (magnitude & 0xffff) as u16;
                magnitude >>= 16;
            }
            ensure!(magnitude == 0, "softmax magnitude exceeds five digits");
        }
    }
    let mut probabilities = [[0; SEQUENCE]; SEQUENCE];
    for query in 0..SEQUENCE {
        let products = std::array::from_fn::<_, SEQUENCE, _>(|key| {
            if key <= query {
                softmax_product(shifted_magnitudes[query][key])
            } else {
                0
            }
        });
        let sum = products.iter().sum::<i64>();
        for key in 0..SEQUENCE {
            probabilities[query][key] = if key == query {
                (1 << Q20_SHIFT) - probabilities[query][..key].iter().sum::<i32>()
            } else if key < query {
                ((products[key] * (1 << Q20_SHIFT) + sum / 2) / sum) as i32
            } else {
                0
            };
        }
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
    let attention_residual = add(&input, &attention_projection)?;
    let post_energy = energy(&attention_residual)?;
    let post_inv_rms = post_energy.map(rms_inv);
    let post_norm = rms_norm(&attention_residual, &post_inv_rms, &POST_NORM_WEIGHT)?;
    let gate = matmul(&post_norm, &GATE_WEIGHT, Some(Q20_SHIFT))?;
    let up = matmul(&post_norm, &UP_WEIGHT, Some(Q16_SHIFT))?;
    let swiglu = gate.map(|row| {
        row.map(|value| {
            (f64::from(value) * 16.0 / (1.0 + (-f64::from(value) / 4096.0).exp())).round() as i32
        })
    });
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
        layer,
        input,
        input_inv_rms,
        input_energy,
        input_norm,
        q_projection,
        k_projection,
        v,
        q_rope,
        k_rope,
        qk_scores,
        shifted_magnitudes,
        softmax_digits,
        probabilities,
        attention,
        attention_projection,
        attention_residual,
        post_energy,
        post_inv_rms,
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
