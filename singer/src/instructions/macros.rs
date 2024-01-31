macro_rules! register_wires_in {
    ($struct_name:ident, $($wire_name:ident { $($slice_name:ident => $length:expr),* }),*) => {
        impl $struct_name {
            $(
                #[inline]
                pub fn $wire_name() -> usize {
                    (0 $(+ $length)* as usize).next_power_of_two()
                }

                register_wires_in!(@internal $wire_name, 0usize; $($slice_name => $length),*);
            )*
        }
    };

    ($struct_name:ident<N>, $($wire_name:ident { $($slice_name:ident => $length:expr),* }),*) => {
        impl<const N: usize> $struct_name<N> {
            $(
                #[inline]
                pub fn $wire_name() -> usize {
                    (0 $(+ $length)* as usize).next_power_of_two()
                }

                register_wires_in!(@internal $wire_name, 0usize; $($slice_name => $length),*);
            )*
        }
    };

    (@internal $wire_name:ident, $offset:expr; $name:ident => $length:expr $(, $rest:ident => $rest_length:expr)*) => {
        fn $name() -> std::ops::Range<usize> {
            $offset..$offset + $length
        }
        register_wires_in!(@internal $wire_name, $offset + $length; $($rest => $rest_length),*);
    };

    (@internal $wire_name:ident, $offset:expr;) => {};
}

macro_rules! register_wires_out {
    ($struct_name:ident, $($wire_name:ident { $($slice_name:ident => $length:expr),* }),*) => {
        impl $struct_name {
            $(
                #[inline]
                pub fn $wire_name() -> usize {
                    (0 $(+ $length)* as usize).next_power_of_two()
                }
            )*
        }
    };

    ($struct_name:ident<N>, $($wire_name:ident { $($slice_name:ident => $length:expr),* }),*) => {
        impl<const N: usize> $struct_name<N> {
            $(
                #[inline]
                pub fn $wire_name() -> usize {
                    (0 $(+ $length)* as usize).next_power_of_two()
                }
            )*
        }
    };
}

macro_rules! register_succ_wire_out {
    ($struct_name:ident, $($succ_name:ident),*) => {
        impl $struct_name {
            register_succ_wire_out!(@internal 0usize; $($succ_name),*);
        }
    };

    (@internal $offset:expr; $name:ident $(, $rest:ident)*) => {
        fn $name() -> usize {
            $offset
        }
        register_succ_wire_out!(@internal $offset + 1; $($rest),*);
    };

    (@internal $offset:expr;) => {
        fn succ_wire_out_num() -> usize {
            $offset
        }
    };
}

macro_rules! copy_pc_from_record {
    ($wire_values: expr, $record: expr) => {
        $wire_values[Self::phase0_pc()].copy_from_slice(&PCUInt::uint_to_field_elems($record.pc));
    };
}

macro_rules! copy_stack_ts_from_record {
    ($wire_values: expr, $record: expr) => {
        $wire_values[Self::phase0_stack_ts()]
            .copy_from_slice(&TSUInt::uint_to_field_elems($record.stack_timestamp));
    };
}

macro_rules! copy_memory_ts_from_record {
    ($wire_values: expr, $record: expr) => {
        $wire_values[..].copy_from_slice(&TSUInt::uint_to_field_elems($record.memory_timestamp));
    };
}

macro_rules! copy_stack_top_from_record {
    ($wire_values: expr, $record: expr) => {
        $wire_values[Self::phase0_stack_top()]
            .copy_from_slice(&u2fvec::<F, 1, 64>($record.stack_top));
    };
}

macro_rules! copy_clock_from_record {
    ($wire_values: expr, $record: expr) => {
        $wire_values[Self::phase0_clk()].copy_from_slice(&u2fvec::<F, 1, 64>($record.clock));
    };
}

macro_rules! copy_pc_add_from_record {
    ($wire_values: expr, $record: expr) => {
        $wire_values[Self::phase0_pc_add()].copy_from_slice(
            &UIntAddSub::<PCUInt>::compute_no_overflow_carries($record.pc, 1),
        );
    };
}

macro_rules! copy_stack_ts_add_from_record {
    ($wire_values: expr, $record: expr) => {
        $wire_values[UIntAddSub::<TSUInt>::range_values_no_overflow_range(
            Self::phase0_stack_ts_add().start,
        )]
        .copy_from_slice(&TSUInt::uint_to_range_no_overflow_field_limbs(
            $record.stack_timestamp + 1,
        ));
        $wire_values
            [UIntAddSub::<TSUInt>::carry_no_overflow_range(Self::phase0_stack_ts_add().start)]
        .copy_from_slice(&UIntAddSub::<TSUInt>::compute_no_overflow_carries(
            $record.stack_timestamp,
            1,
        ));
    };
}

macro_rules! copy_stack_ts_lt_from_record {
    ($wire_values: expr, $record: expr, 0) => {
        copy_operand_timestamp_from_record!($wire_values, $record, phase0_old_stack_ts0, 0);

        $wire_values
            [UIntAddSub::<TSUInt>::carry_no_overflow_range(Self::phase0_old_stack_ts_lt0().start)]
        .copy_from_slice(&UIntAddSub::<TSUInt>::compute_no_overflow_borrows(
            $record.operands_timestamps[0],
            $record.stack_timestamp,
        ));

        $wire_values[UIntAddSub::<TSUInt>::range_values_no_overflow_range(
            Self::phase0_old_stack_ts_lt0().start,
        )]
        .copy_from_slice(&TSUInt::uint_to_range_no_overflow_field_limbs(
            $record.operands_timestamps[0] + (1 << TSUInt::BIT_SIZE) - $record.stack_timestamp,
        ));
    };

    ($wire_values: expr, $record: expr, 1) => {
        copy_operand_timestamp_from_record!($wire_values, $record, phase0_old_stack_ts1, 0);

        $wire_values
            [UIntAddSub::<TSUInt>::carry_no_overflow_range(Self::phase0_old_stack_ts_lt1().start)]
        .copy_from_slice(&UIntAddSub::<TSUInt>::compute_no_overflow_borrows(
            $record.operands_timestamps[1],
            $record.stack_timestamp,
        ));

        $wire_values[UIntAddSub::<TSUInt>::range_values_no_overflow_range(
            Self::phase0_old_stack_ts_lt1().start,
        )]
        .copy_from_slice(&TSUInt::uint_to_range_no_overflow_field_limbs(
            $record.operands_timestamps[1] + (1 << TSUInt::BIT_SIZE) - $record.stack_timestamp,
        ));
    };

    ($wire_values: expr, $record: expr) => {
        copy_operand_timestamp_from_record!($wire_values, $record, phase0_old_stack_ts, 0);
        $wire_values
            [UIntAddSub::<TSUInt>::carry_no_overflow_range(Self::phase0_old_stack_ts_lt().start)]
        .copy_from_slice(&UIntAddSub::<TSUInt>::compute_no_overflow_borrows(
            $record.operands_timestamps[0],
            $record.stack_timestamp,
        ));
        $wire_values[UIntAddSub::<TSUInt>::range_values_no_overflow_range(
            Self::phase0_old_stack_ts_lt().start,
        )]
        .copy_from_slice(&TSUInt::uint_to_range_no_overflow_field_limbs(
            $record.operands_timestamps[0] + (1 << TSUInt::BIT_SIZE) - $record.stack_timestamp,
        ));
    };
}

macro_rules! copy_operand_from_record {
    ($wire_values: expr, $record: expr, $dst_slice: tt, $index: expr) => {
        $wire_values[Self::$dst_slice()]
            .copy_from_slice(&StackUInt::u256_to_field_elems($record.operands[$index]));
    };
}

macro_rules! copy_operand_u64_from_record {
    ($wire_values: expr, $record: expr, $dst_slice: tt, $index: expr) => {
        $wire_values[Self::$dst_slice()].copy_from_slice(&UInt64::uint_to_field_elems(
            $record.operands[$index].as_limbs()[0],
        ));
    };
}

macro_rules! copy_operand_timestamp_from_record {
    ($wire_values: expr, $record: expr, $dst_slice: tt, $index: expr) => {
        $wire_values[Self::$dst_slice()].copy_from_slice(&TSUInt::uint_to_field_elems(
            $record.operands_timestamps[$index],
        ));
    };
}

macro_rules! copy_range_values_from_u256 {
    ($wire_values: expr, $dst_slice: tt, $val: expr) => {
        $wire_values[UIntAddSub::<StackUInt>::range_values_range(Self::$dst_slice().start)]
            .copy_from_slice(&StackUInt::u256_to_range_field_limbs($val));
    };
}

macro_rules! copy_carry_values_from_addends {
    ($wire_values: expr, $dst_slice: tt, $lval: expr, $rval: expr) => {
        $wire_values[UIntAddSub::<StackUInt>::carry_range(Self::$dst_slice().start)]
            .copy_from_slice(&UIntAddSub::<StackUInt>::compute_carries_u256($lval, $rval));
    };
}
