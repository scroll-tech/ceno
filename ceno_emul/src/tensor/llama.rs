//! Integer reference semantics for a statically generated Llama layer.
//!
//! This module is deliberately independent of proving code.  It is the oracle
//! used by the progressively-added AIRs and records every rescale remainder so
//! a circuit cannot silently use host floating point.  The reduced fixture has
//! Llama's topology, while production dimensions remain 4096/32/128/11008.

use anyhow::{Result, ensure};

use super::{matmul_rescaled_i32, zkllm_rescale};

pub const LLAMA2_7B_HIDDEN: usize = 4096;
pub const LLAMA2_7B_HEADS: usize = 32;
pub const LLAMA2_7B_HEAD_DIM: usize = 128;
pub const LLAMA2_7B_INTERMEDIATE: usize = 11008;
pub const VALUE_SHIFT: u32 = 16;
pub const ACCUMULATION_SHIFT: u32 = 20;
pub const ZKLLM_ATTN_RADICES: [u64; 3] = [1 << 8, 1 << 20, 1 << 20];
pub const ZKLLM_ATTN_TABLE_SCALES: [i64; 2] = [1 << 18, 1 << 22];

#[derive(Clone, Debug)]
pub struct ZkllmSegmentedAttentionTables {
    /// Fixed digit-to-value tables for the middle and most-significant
    /// segments. The least-significant base-2^8 digit is range-checked only,
    /// exactly as `zkSoftmax(..., L=1, M=0, ...)` at revision 993311e.
    pub middle_q18: Vec<(u32, i64)>,
    pub high_q22: Vec<(u32, i64)>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ZkllmSegmentedAttentionTrace {
    pub scores: Vec<i64>,
    pub shifted: Vec<i64>,
    pub digits: Vec<[u32; 3]>,
    pub exponent_products: Vec<i64>,
    pub once_rescaled: Vec<i64>,
    pub output: Vec<i32>,
}

fn fixed_segment_value(table: &[(u32, i64)], digit: u32) -> Result<i64> {
    table
        .iter()
        .find_map(|(candidate, value)| (*candidate == digit).then_some(*value))
        .ok_or_else(|| anyhow::anyhow!("segmented attention table miss for digit {digit}"))
}

/// Integer oracle for the published zkLLM C++ attention data path. `shifts`
/// are the integer outputs of its floating-point row-shift preprocessing; the
/// proof relation starts from those values. Ceno additionally applies an
/// explicit causal mask, since the published `self-attn.cu` does not do so.
pub fn zkllm_segmented_attention(
    q: &[i32],
    k: &[i32],
    v: &[i32],
    shifts: &[i64],
    tables: &ZkllmSegmentedAttentionTables,
    sequence: usize,
    width: usize,
) -> Result<ZkllmSegmentedAttentionTrace> {
    ensure!(q.len() == sequence * width, "Q shape mismatch");
    ensure!(
        k.len() == q.len() && v.len() == q.len(),
        "K/V shape mismatch"
    );
    ensure!(shifts.len() == sequence, "attention shift shape mismatch");
    let mut scores = Vec::with_capacity(sequence * sequence);
    let mut shifted = Vec::with_capacity(sequence * sequence);
    let mut digits = Vec::with_capacity(sequence * sequence);
    let mut exponent_products = Vec::with_capacity(sequence * sequence);
    for query in 0..sequence {
        for key in 0..sequence {
            let score = (0..width).try_fold(0i64, |sum, dim| {
                sum.checked_add(i64::from(q[query * width + dim]) * i64::from(k[key * width + dim]))
                    .ok_or_else(|| anyhow::anyhow!("attention score overflow"))
            })?;
            let shifted_score = score
                .checked_sub(shifts[query])
                .ok_or_else(|| anyhow::anyhow!("attention shift overflow"))?;
            ensure!(
                shifted_score <= 0,
                "zkLLM shift must upper-bound every row score"
            );
            let mut magnitude = shifted_score.unsigned_abs();
            let mut decomposition = [0u32; 3];
            for (digit, radix) in decomposition.iter_mut().zip(ZKLLM_ATTN_RADICES) {
                *digit = u32::try_from(magnitude % radix)?;
                magnitude /= radix;
            }
            ensure!(
                magnitude == 0,
                "shifted score exceeds segmented radix domain"
            );
            let product = if key > query {
                0
            } else {
                fixed_segment_value(&tables.middle_q18, decomposition[1])?
                    .checked_mul(fixed_segment_value(&tables.high_q22, decomposition[2])?)
                    .ok_or_else(|| anyhow::anyhow!("segmented table product overflow"))?
            };
            scores.push(score);
            shifted.push(shifted_score);
            digits.push(decomposition);
            exponent_products.push(product);
        }
    }

    let mut once_rescaled = Vec::with_capacity(sequence * width);
    let mut output = Vec::with_capacity(sequence * width);
    for query in 0..sequence {
        for dim in 0..width {
            let accum = (0..sequence).try_fold(0i64, |sum, key| {
                exponent_products[query * sequence + key]
                    .checked_mul(i64::from(v[key * width + dim]))
                    .and_then(|term| sum.checked_add(term))
                    .ok_or_else(|| anyhow::anyhow!("attention value overflow"))
            })?;
            let first = zkllm_rescale(accum, ACCUMULATION_SHIFT)?.0;
            let second = zkllm_rescale(first, ACCUMULATION_SHIFT)?.0;
            once_rescaled.push(first);
            output.push(i32::try_from(second)?);
        }
    }
    Ok(ZkllmSegmentedAttentionTrace {
        scores,
        shifted,
        digits,
        exponent_products,
        once_rescaled,
        output,
    })
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StaticLlamaShape {
    pub sequence: usize,
    pub hidden: usize,
    pub heads: usize,
    pub head_dim: usize,
    pub intermediate: usize,
}

impl StaticLlamaShape {
    pub const REDUCED_GATE3: Self = Self {
        sequence: 2,
        hidden: 4,
        heads: 2,
        head_dim: 2,
        intermediate: 6,
    };

    pub fn validate(self) -> Result<()> {
        ensure!(self.sequence > 0, "sequence must be nonzero");
        ensure!(
            self.hidden == self.heads * self.head_dim,
            "head shape mismatch"
        );
        ensure!(
            self.head_dim.is_multiple_of(2),
            "RoPE needs an even head dimension"
        );
        ensure!(
            self.intermediate > 0,
            "intermediate dimension must be nonzero"
        );
        Ok(())
    }
}

#[derive(Clone, Debug)]
pub struct StaticLlamaLayerWeights {
    pub input_norm: Vec<i32>,
    pub q: Vec<i32>,
    pub k: Vec<i32>,
    pub v: Vec<i32>,
    pub o: Vec<i32>,
    pub post_norm: Vec<i32>,
    pub gate: Vec<i32>,
    pub up: Vec<i32>,
    pub down: Vec<i32>,
}

#[derive(Clone, Debug)]
pub struct StaticLlamaLayerAux {
    /// Per-token Q16 inverse RMS values, calculated by the same committed
    /// lookup/oracle relation as zkLLM's `rms_inv_temp`.
    pub input_inv_rms: Vec<i32>,
    pub post_inv_rms: Vec<i32>,
    /// Row-major `[sequence, head_dim]` Q16 RoPE tables.
    pub rope_cos: Vec<i32>,
    pub rope_sin: Vec<i32>,
    /// Q20 causal softmax output, `[heads, query, key]`.  Gate 3 treats this as
    /// a lookup output and validates masking and row normalization here.
    pub attention_probabilities: Vec<i32>,
    /// Per-head/query Q20 log-normalization shifts and the fixed lookup table
    /// used to bind shifted Q20 scores to probability values.
    pub attention_shifts: Vec<i32>,
    pub attention_lookup: Vec<(i32, i32)>,
    /// Q16 outputs of the versioned zkLLM SwiGLU lookup.
    pub swiglu: Vec<i32>,
    /// Fixed `(gate_q20, swiglu_q16)` lookup entries for this profile.
    pub swiglu_lookup: Vec<(i32, i32)>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StaticLlamaLayerTrace {
    pub input_norm: Vec<i32>,
    pub q: Vec<i32>,
    pub k: Vec<i32>,
    pub v: Vec<i32>,
    pub attention: Vec<i32>,
    pub attention_projection: Vec<i32>,
    pub attention_residual: Vec<i32>,
    pub post_norm: Vec<i32>,
    pub gate: Vec<i32>,
    pub up: Vec<i32>,
    pub swiglu: Vec<i32>,
    pub down: Vec<i32>,
    pub output: Vec<i32>,
}

fn checked_add(left: &[i32], right: &[i32]) -> Result<Vec<i32>> {
    ensure!(left.len() == right.len(), "residual shape mismatch");
    left.iter()
        .zip(right)
        .map(|(&a, &b)| i32::try_from(i64::from(a) + i64::from(b)).map_err(Into::into))
        .collect()
}

fn rmsnorm(
    input: &[i32],
    inv_rms: &[i32],
    weight: &[i32],
    rows: usize,
    width: usize,
) -> Result<Vec<i32>> {
    ensure!(input.len() == rows * width, "RMSNorm input shape mismatch");
    ensure!(inv_rms.len() == rows, "RMSNorm inverse shape mismatch");
    ensure!(weight.len() == width, "RMSNorm weight shape mismatch");
    let mut out = Vec::with_capacity(input.len());
    for row in 0..rows {
        for column in 0..width {
            let (weighted_inv, _) = zkllm_rescale(
                i64::from(inv_rms[row]) * i64::from(weight[column]),
                VALUE_SHIFT,
            )?;
            let (value, _) = zkllm_rescale(
                weighted_inv * i64::from(input[row * width + column]),
                VALUE_SHIFT,
            )?;
            out.push(i32::try_from(value)?);
        }
    }
    Ok(out)
}

fn rope(values: &[i32], cos: &[i32], sin: &[i32], shape: StaticLlamaShape) -> Result<Vec<i32>> {
    ensure!(
        values.len() == shape.sequence * shape.hidden,
        "RoPE value shape mismatch"
    );
    ensure!(
        cos.len() == shape.sequence * shape.head_dim,
        "RoPE cosine shape mismatch"
    );
    ensure!(sin.len() == cos.len(), "RoPE sine shape mismatch");
    let half = shape.head_dim / 2;
    let mut out = vec![0; values.len()];
    for token in 0..shape.sequence {
        for head in 0..shape.heads {
            for dim in 0..shape.head_dim {
                let index = token * shape.hidden + head * shape.head_dim + dim;
                let rotated_dim = if dim < half { dim + half } else { dim - half };
                let rotated_index = token * shape.hidden + head * shape.head_dim + rotated_dim;
                let rotated = if dim < half {
                    -i64::from(values[rotated_index])
                } else {
                    i64::from(values[rotated_index])
                };
                let accum = i64::from(values[index]) * i64::from(cos[token * shape.head_dim + dim])
                    + rotated * i64::from(sin[token * shape.head_dim + dim]);
                out[index] = i32::try_from(zkllm_rescale(accum, VALUE_SHIFT)?.0)?;
            }
        }
    }
    Ok(out)
}

fn causal_attention(
    q: &[i32],
    k: &[i32],
    v: &[i32],
    probabilities: &[i32],
    aux: &StaticLlamaLayerAux,
    shape: StaticLlamaShape,
) -> Result<Vec<i32>> {
    ensure!(
        q.len() == shape.sequence * shape.hidden && k.len() == q.len() && v.len() == q.len(),
        "attention tensor shape mismatch"
    );
    ensure!(
        probabilities.len() == shape.heads * shape.sequence * shape.sequence,
        "softmax shape mismatch"
    );
    ensure!(
        aux.attention_shifts.len() == shape.heads * shape.sequence,
        "softmax shift shape mismatch"
    );
    let probability_scale = 1i64 << ACCUMULATION_SHIFT;
    let mut out = vec![0; v.len()];
    for head in 0..shape.heads {
        for query in 0..shape.sequence {
            let mut row_sum = 0i64;
            for key in 0..shape.sequence {
                let p = probabilities[(head * shape.sequence + query) * shape.sequence + key];
                ensure!(p >= 0, "negative softmax value");
                ensure!(key <= query || p == 0, "causal mask violation");
                row_sum += i64::from(p);
            }
            ensure!(
                row_sum == probability_scale,
                "softmax row is not Q20-normalized"
            );
            for key in 0..=query {
                let mut score = 0i64;
                for dim in 0..shape.head_dim {
                    let qi = query * shape.hidden + head * shape.head_dim + dim;
                    let ki = key * shape.hidden + head * shape.head_dim + dim;
                    score = score
                        .checked_add(i64::from(q[qi]) * i64::from(k[ki]))
                        .ok_or_else(|| anyhow::anyhow!("attention score overflow"))?;
                }
                // Q16*Q16 -> Q20, matching zkLLM's attention accumulator.
                let score_q20 = i32::try_from(zkllm_rescale(score, 12)?.0)?;
                let shifted = score_q20
                    .checked_sub(aux.attention_shifts[head * shape.sequence + query])
                    .ok_or_else(|| anyhow::anyhow!("attention shift overflow"))?;
                let expected = aux
                    .attention_lookup
                    .iter()
                    .find_map(|&(input, output)| (input == shifted).then_some(output))
                    .ok_or_else(|| anyhow::anyhow!("attention lookup miss"))?;
                let actual = probabilities[(head * shape.sequence + query) * shape.sequence + key];
                ensure!(actual == expected, "attention lookup mismatch");
            }
            for dim in 0..shape.head_dim {
                let mut accum = 0i64;
                for key in 0..shape.sequence {
                    let p = i64::from(
                        probabilities[(head * shape.sequence + query) * shape.sequence + key],
                    );
                    let vi = key * shape.hidden + head * shape.head_dim + dim;
                    accum = accum
                        .checked_add(p * i64::from(v[vi]))
                        .ok_or_else(|| anyhow::anyhow!("attention value overflow"))?;
                }
                out[query * shape.hidden + head * shape.head_dim + dim] =
                    i32::try_from(zkllm_rescale(accum, ACCUMULATION_SHIFT)?.0)?;
            }
        }
    }
    Ok(out)
}

fn hadamard_rescaled(left: &[i32], right: &[i32]) -> Result<Vec<i32>> {
    ensure!(left.len() == right.len(), "Hadamard shape mismatch");
    left.iter()
        .zip(right)
        .map(|(&a, &b)| {
            Ok(i32::try_from(
                zkllm_rescale(i64::from(a) * i64::from(b), VALUE_SHIFT)?.0,
            )?)
        })
        .collect()
}

pub fn execute_static_llama_layer(
    shape: StaticLlamaShape,
    input: &[i32],
    weights: &StaticLlamaLayerWeights,
    aux: &StaticLlamaLayerAux,
) -> Result<StaticLlamaLayerTrace> {
    shape.validate()?;
    ensure!(
        input.len() == shape.sequence * shape.hidden,
        "layer input shape mismatch"
    );
    let input_norm = rmsnorm(
        input,
        &aux.input_inv_rms,
        &weights.input_norm,
        shape.sequence,
        shape.hidden,
    )?;
    let q = rope(
        &matmul_rescaled_i32(
            &input_norm,
            &weights.q,
            shape.sequence,
            shape.hidden,
            shape.hidden,
            VALUE_SHIFT,
        )?
        .0,
        &aux.rope_cos,
        &aux.rope_sin,
        shape,
    )?;
    let k = rope(
        &matmul_rescaled_i32(
            &input_norm,
            &weights.k,
            shape.sequence,
            shape.hidden,
            shape.hidden,
            VALUE_SHIFT,
        )?
        .0,
        &aux.rope_cos,
        &aux.rope_sin,
        shape,
    )?;
    let v = matmul_rescaled_i32(
        &input_norm,
        &weights.v,
        shape.sequence,
        shape.hidden,
        shape.hidden,
        VALUE_SHIFT,
    )?
    .0;
    let attention = causal_attention(&q, &k, &v, &aux.attention_probabilities, aux, shape)?;
    let attention_projection = matmul_rescaled_i32(
        &attention,
        &weights.o,
        shape.sequence,
        shape.hidden,
        shape.hidden,
        VALUE_SHIFT,
    )?
    .0;
    let attention_residual = checked_add(input, &attention_projection)?;
    let post_norm = rmsnorm(
        &attention_residual,
        &aux.post_inv_rms,
        &weights.post_norm,
        shape.sequence,
        shape.hidden,
    )?;
    let gate = matmul_rescaled_i32(
        &post_norm,
        &weights.gate,
        shape.sequence,
        shape.hidden,
        shape.intermediate,
        ACCUMULATION_SHIFT,
    )?
    .0;
    let up = matmul_rescaled_i32(
        &post_norm,
        &weights.up,
        shape.sequence,
        shape.hidden,
        shape.intermediate,
        VALUE_SHIFT,
    )?
    .0;
    ensure!(
        aux.swiglu.len() == gate.len(),
        "SwiGLU lookup shape mismatch"
    );
    for (&input, &output) in gate.iter().zip(&aux.swiglu) {
        let expected = aux
            .swiglu_lookup
            .iter()
            .find_map(|&(table_input, table_output)| (table_input == input).then_some(table_output))
            .ok_or_else(|| anyhow::anyhow!("SwiGLU lookup miss"))?;
        ensure!(output == expected, "SwiGLU lookup mismatch");
    }
    let swiglu = aux.swiglu.clone();
    let down_input = hadamard_rescaled(&swiglu, &up)?;
    let down = matmul_rescaled_i32(
        &down_input,
        &weights.down,
        shape.sequence,
        shape.intermediate,
        shape.hidden,
        VALUE_SHIFT,
    )?
    .0;
    let output = checked_add(&attention_residual, &down)?;
    Ok(StaticLlamaLayerTrace {
        input_norm,
        q,
        k,
        v,
        attention,
        attention_projection,
        attention_residual,
        post_norm,
        gate,
        up,
        swiglu,
        down,
        output,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn identity(rows: usize, cols: usize) -> Vec<i32> {
        let mut values = vec![0; rows * cols];
        for i in 0..rows.min(cols) {
            values[i * cols + i] = 1 << VALUE_SHIFT;
        }
        values
    }

    #[test]
    fn pinned_zkllm_segmented_attention_fixture_and_tamper() {
        let q = [1, 0, 0, 1];
        let k = [1, 0, 0, 1];
        let v = [2, 4, 6, 8];
        // Row zero has equal score/shift for its only causal key. Row one's
        // older key is exactly one middle-radix unit below its shift.
        let shifts = [1, 256];
        let tables = ZkllmSegmentedAttentionTables {
            middle_q18: vec![(0, ZKLLM_ATTN_TABLE_SCALES[0]), (1, 1 << 17)],
            high_q22: vec![(0, ZKLLM_ATTN_TABLE_SCALES[1])],
        };
        let trace = zkllm_segmented_attention(&q, &k, &v, &shifts, &tables, 2, 2).unwrap();
        assert_eq!(trace.scores, vec![1, 0, 0, 1]);
        assert_eq!(trace.shifted, vec![0, -1, -256, -255]);
        assert_eq!(trace.digits[2], [0, 1, 0]);
        // The future-key product is zero due to Ceno's explicit causal mask.
        assert_eq!(trace.exponent_products[1], 0);
        assert_eq!(trace.output, vec![2, 4, 7, 10]);

        let mut tampered = tables.clone();
        tampered.middle_q18.retain(|(digit, _)| *digit != 1);
        assert!(zkllm_segmented_attention(&q, &k, &v, &shifts, &tampered, 2, 2).is_err());
    }

    fn fixture() -> (Vec<i32>, StaticLlamaLayerWeights, StaticLlamaLayerAux) {
        let s = StaticLlamaShape::REDUCED_GATE3;
        let input = vec![1, -2, 3, -4, 5, 6, -7, 8];
        let weights = StaticLlamaLayerWeights {
            input_norm: vec![1 << 16; 4],
            q: identity(4, 4),
            k: identity(4, 4),
            v: identity(4, 4),
            o: identity(4, 4),
            post_norm: vec![1 << 16; 4],
            gate: vec![1 << 16; 4 * 6],
            up: vec![1 << 16; 4 * 6],
            down: vec![1 << 16; 6 * 4],
        };
        let aux = StaticLlamaLayerAux {
            input_inv_rms: vec![1 << 16; 2],
            post_inv_rms: vec![1 << 16; 2],
            rope_cos: vec![1 << 16; s.sequence * s.head_dim],
            rope_sin: vec![0; s.sequence * s.head_dim],
            attention_probabilities: vec![
                1 << 20,
                0,
                1 << 19,
                1 << 19,
                1 << 20,
                0,
                1 << 19,
                1 << 19,
            ],
            attention_shifts: vec![0, 1, 0, 1],
            attention_lookup: vec![(0, 1 << 20), (-1, 1 << 19)],
            swiglu: vec![1 << 16; s.sequence * s.intermediate],
            swiglu_lookup: (-256..=256).map(|input| (input, 1 << 16)).collect(),
        };
        (input, weights, aux)
    }

    #[test]
    fn reduced_layer_is_deterministic_and_topology_complete() {
        let (input, weights, aux) = fixture();
        let a = execute_static_llama_layer(StaticLlamaShape::REDUCED_GATE3, &input, &weights, &aux)
            .unwrap();
        let b = execute_static_llama_layer(StaticLlamaShape::REDUCED_GATE3, &input, &weights, &aux)
            .unwrap();
        assert_eq!(a, b);
        assert_eq!(a.output, [-22, -28, -18, -32, 110, 110, 93, 112]);
        assert_eq!(a.output.len(), input.len());
        assert_eq!(a.gate.len(), 12);
    }

    #[test]
    fn causal_mask_and_normalization_fail_closed() {
        let (input, weights, mut aux) = fixture();
        aux.attention_probabilities[1] = 1;
        assert!(
            execute_static_llama_layer(StaticLlamaShape::REDUCED_GATE3, &input, &weights, &aux)
                .is_err()
        );
        let (input, weights, mut aux) = fixture();
        aux.attention_probabilities[0] -= 1;
        assert!(
            execute_static_llama_layer(StaticLlamaShape::REDUCED_GATE3, &input, &weights, &aux)
                .is_err()
        );
    }

    #[test]
    fn shape_tamper_fails_closed() {
        let (input, weights, aux) = fixture();
        let mut shape = StaticLlamaShape::REDUCED_GATE3;
        shape.hidden = 5;
        assert!(execute_static_llama_layer(shape, &input, &weights, &aux).is_err());
    }

    #[test]
    fn nonlinear_lookup_tamper_fails_closed() {
        let (input, weights, mut aux) = fixture();
        aux.swiglu[0] -= 1;
        assert!(
            execute_static_llama_layer(StaticLlamaShape::REDUCED_GATE3, &input, &weights, &aux)
                .is_err()
        );
        let (input, weights, mut aux) = fixture();
        aux.attention_lookup[0].1 -= 1;
        assert!(
            execute_static_llama_layer(StaticLlamaShape::REDUCED_GATE3, &input, &weights, &aux)
                .is_err()
        );
    }
}
