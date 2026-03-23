use gkr_iop::{
    gadgets::{AssertLtConfig, cal_lt_diff},
    tables::{LookupTable, OpsTable},
};

use crate::instructions::riscv::constants::{LIMB_BITS, UINT_LIMBS};

use super::{LkOp, SideEffectSink};

pub fn emit_assert_lt_ops(
    sink: &mut impl SideEffectSink,
    lt_cfg: &AssertLtConfig,
    lhs: u64,
    rhs: u64,
) {
    let max_bits = lt_cfg.0.max_bits;
    let diff = cal_lt_diff(lhs < rhs, max_bits, lhs, rhs);
    for i in 0..(max_bits / u16::BITS as usize) {
        let value = ((diff >> (i * u16::BITS as usize)) & 0xffff) as u16;
        sink.emit_lk(LkOp::AssertU16 { value });
    }
    let remain_bits = max_bits % u16::BITS as usize;
    if remain_bits > 1 {
        let value = (diff >> ((lt_cfg.0.diff.len() - 1) * u16::BITS as usize)) & 0xffff;
        sink.emit_lk(LkOp::DynamicRange {
            value,
            bits: remain_bits as u32,
        });
    }
}

pub fn emit_u16_limbs(sink: &mut impl SideEffectSink, value: u32) {
    sink.emit_lk(LkOp::AssertU16 {
        value: (value & 0xffff) as u16,
    });
    sink.emit_lk(LkOp::AssertU16 {
        value: (value >> 16) as u16,
    });
}

pub fn emit_const_range_op(sink: &mut impl SideEffectSink, value: u64, bits: usize) {
    match bits {
        0 | 1 => {}
        14 => sink.emit_lk(LkOp::AssertU14 {
            value: value as u16,
        }),
        16 => sink.emit_lk(LkOp::AssertU16 {
            value: value as u16,
        }),
        _ => sink.emit_lk(LkOp::DynamicRange {
            value,
            bits: bits as u32,
        }),
    }
}

pub fn emit_byte_decomposition_ops(sink: &mut impl SideEffectSink, bytes: &[u8]) {
    for chunk in bytes.chunks(2) {
        match chunk {
            [a, b] => sink.emit_lk(LkOp::DoubleU8 { a: *a, b: *b }),
            [a] => emit_const_range_op(sink, *a as u64, 8),
            _ => unreachable!(),
        }
    }
}

pub fn emit_signed_extend_op(sink: &mut impl SideEffectSink, n_bits: usize, value: u64) {
    let msb = value >> (n_bits - 1);
    sink.emit_lk(LkOp::DynamicRange {
        value: 2 * value - (msb << n_bits),
        bits: n_bits as u32,
    });
}

pub fn emit_logic_u8_ops<OP: OpsTable>(
    sink: &mut impl SideEffectSink,
    lhs: u64,
    rhs: u64,
    num_bytes: usize,
) {
    for i in 0..num_bytes {
        let a = ((lhs >> (i * 8)) & 0xff) as u8;
        let b = ((rhs >> (i * 8)) & 0xff) as u8;
        let op = match OP::ROM_TYPE {
            LookupTable::And => LkOp::And { a, b },
            LookupTable::Or => LkOp::Or { a, b },
            LookupTable::Xor => LkOp::Xor { a, b },
            LookupTable::Ltu => LkOp::Ltu { a, b },
            rom_type => unreachable!("unsupported logic table: {rom_type:?}"),
        };
        sink.emit_lk(op);
    }
}

pub fn emit_uint_limbs_lt_ops(
    sink: &mut impl SideEffectSink,
    is_sign_comparison: bool,
    a: &[u16],
    b: &[u16],
) {
    assert_eq!(a.len(), UINT_LIMBS);
    assert_eq!(b.len(), UINT_LIMBS);

    let last = UINT_LIMBS - 1;
    let sign_mask = 1 << (LIMB_BITS - 1);
    let is_a_neg = is_sign_comparison && (a[last] & sign_mask) != 0;
    let is_b_neg = is_sign_comparison && (b[last] & sign_mask) != 0;

    let (cmp_lt, diff_idx) = (0..UINT_LIMBS)
        .rev()
        .find(|&i| a[i] != b[i])
        .map(|i| ((a[i] < b[i]) ^ is_a_neg ^ is_b_neg, i))
        .unwrap_or((false, UINT_LIMBS));

    let a_msb_range = if is_a_neg {
        a[last] - sign_mask
    } else {
        a[last] + ((is_sign_comparison as u16) << (LIMB_BITS - 1))
    };
    let b_msb_range = if is_b_neg {
        b[last] - sign_mask
    } else {
        b[last] + ((is_sign_comparison as u16) << (LIMB_BITS - 1))
    };

    let to_signed = |value: u16, is_neg: bool| -> i32 {
        if is_neg {
            value as i32 - (1 << LIMB_BITS)
        } else {
            value as i32
        }
    };
    let diff_val = if diff_idx == UINT_LIMBS {
        0
    } else if diff_idx == last {
        let a_signed = to_signed(a[last], is_a_neg);
        let b_signed = to_signed(b[last], is_b_neg);
        if cmp_lt {
            (b_signed - a_signed) as u16
        } else {
            (a_signed - b_signed) as u16
        }
    } else if cmp_lt {
        b[diff_idx] - a[diff_idx]
    } else {
        a[diff_idx] - b[diff_idx]
    };

    emit_const_range_op(
        sink,
        if diff_idx == UINT_LIMBS {
            0
        } else {
            (diff_val - 1) as u64
        },
        LIMB_BITS,
    );
    emit_const_range_op(sink, a_msb_range as u64, LIMB_BITS);
    emit_const_range_op(sink, b_msb_range as u64, LIMB_BITS);
}
