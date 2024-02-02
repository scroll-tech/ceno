macro_rules! register_witness {
    ($struct_name:ident, $($wire_name:ident { $($slice_name:ident => $length:expr),* }),*) => {
        paste! {
            impl $struct_name {
                $(
                    #[inline]
                    pub fn [<$wire_name _ size>]() -> usize {
                        (0 $(+ $length)* as usize).next_power_of_two()
                    }

                    register_witness!(@internal $wire_name, 0usize; $($slice_name => $length),*);
                )*
            }
        }
    };

    ($struct_name:ident<N>, $($wire_name:ident { $($slice_name:ident => $length:expr),* }),*) => {
        paste! {
            impl<const N: usize> $struct_name<N> {
                $(
                    #[inline]
                    pub fn [<$wire_name _ size>]() -> usize {
                        (0 $(+ $length)* as usize).next_power_of_two()
                    }

                    register_witness!(@internal $wire_name, 0usize; $($slice_name => $length),*);
                )*
            }
        }
    };

    (@internal $wire_name:ident, $offset:expr; $name:ident => $length:expr $(, $rest:ident => $rest_length:expr)*) => {
        paste! {
            fn [<$wire_name _ $name>]() -> std::ops::Range<usize> {
                $offset..$offset + $length
            }
            register_witness!(@internal $wire_name, $offset + $length; $($rest => $rest_length),*);
        }
    };

    (@internal $wire_name:ident, $offset:expr;) => {};
}
macro_rules! register_witness_multi {
    ($struct_name:ident, $($wire_name:ident($($wire_param:ident)*) { $($slice_name:ident($num:expr) => $length:expr),* }),*) => {
        paste! {
            impl $struct_name {
                $(
                    #[inline]
                    pub fn [<$wire_name _ size>]($($wire_param: usize)*) -> usize {
                        (0 $(+ ($num * $length))* as usize).next_power_of_two()
                    }

                    register_witness_multi!(@internal $wire_name, 0usize; $($slice_name($num) => $length),*);
                )*
            }
        }
    };

    ($struct_name:ident<N>, $($wire_name:ident($($wire_param:ident)*) { $($slice_name:ident($num:expr) => $length:expr),* }),*) => {
        paste! {
            impl<const N: usize> $struct_name<N> {
                $(
                    #[inline]
                    pub fn [<$wire_name _ size>]($($wire_param:ident: usize)*) -> usize {
                        (0 $(+ $length)* as usize).next_power_of_two()
                    }

                    register_witness_multi!(@internal $wire_name, 0usize; $($slice_name($num) => $length),*);
                )*
            }
        }
    };

    (@internal $wire_name:ident, $offset:expr; $name:ident($num:expr) => $length:expr $(, $rest:ident($rest_num:expr) => $rest_length:expr)*) => {
        paste! {
            #[inline]
            fn [<$wire_name _ $name>](idx: usize) -> std::ops::Range<usize> {
                $offset * idx..$offset * idx + $length
            }
            register_witness_multi!(@internal $wire_name, $offset + $length; $($rest($rest_num) => $rest_length),*);
        }
    };

    (@internal $wire_name:ident, $offset:expr;) => {};
}

// macro_rules! register_chips_check {
//     ($struct_name:ident, $($wire_name:ident { $($slice_name:ident => $length:expr),* }),*) => {
//         paste! {
//             impl $struct_name {
//                 $(
//                     #[inline]
//                     pub fn [<$wire_name _ size>]() -> usize {
//                         (0 $(+ $length)* as usize).next_power_of_two()
//                     }
//                 )*
//             }
//         }
//     };

//     ($struct_name:ident<N>, $($wire_name:ident { $($slice_name:ident => $length:expr),* }),*) => {
//         impl<const N: usize> $struct_name<N> {
//             $(
//                 #[inline]
//                 pub fn [<$wire_name _ size>]() -> usize {
//                     (0 $(+ $length)* as usize).next_power_of_two()
//                 }
//             )*
//         }
//     };
// }

// macro_rules! register_chips_check_multi {
//     ($struct_name:ident, $($wire_name:ident($($wire_param:ident)*) { $($slice_name:ident($num:expr) => $length:expr),* }),*) => {
//         paste! {
//             impl $struct_name {
//                 $(
//                     #[inline]
//                     pub fn [<$wire_name _ size>]($($wire_param: usize)*) -> usize {
//                         (0 $(+ $num * $length)* as usize).next_power_of_two()
//                     }
//                 )*
//             }
//         }
//     };

//     ($struct_name:ident<N>, $($wire_name:ident($($wire_param:ident)*) { $($slice_name:ident($num:expr) => $length:expr),* }),*) => {
//         paste! {
//                 impl<const N: usize> $struct_name<N> {
//                 $(
//                     #[inline]
//                     pub fn [<$wire_name _ size>]($($wire_param:ident: usize),*) -> usize {
//                         (0 $(+ $num * $length)* as usize).next_power_of_two()
//                     }
//                 )*
//             }
//         }
//     };
// }

// macro_rules! define_wires_in {
//     ($builder:ident, {$($wire_name:ident $name:ident => $length:expr),*}) => {
//         $(
//             let ($wire_name, $name) = $builder.create_wire_in($length);
//         )*
//     };
// }

// macro_rules! define_wires_out {
//     ($builder:ident, {$($wire_name:ident $name:ident => $length:expr),*}) => {
//         $(
//             let ($wire_name, $name) = $builder.create_wire_out($length);
//         )*
//     };
// }

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
        copy_pc_add_from_record!($wire_values, $record, phase0_pc_add, 1);
    };

    ($wire_values: expr, $record: expr, $dst_slice: tt, $added: expr) => {
        $wire_values[Self::$dst_slice()].copy_from_slice(
            &UIntAddSub::<PCUInt>::compute_no_overflow_carries($record.pc, $added),
        );
    };
}

macro_rules! copy_stack_memory_ts_add_from_record {
    ($wire_values: expr, $record: expr, $dst_slice: tt, $timestamp: tt) => {
        $wire_values
            [UIntAddSub::<TSUInt>::range_values_no_overflow_range(Self::$dst_slice().start)]
        .copy_from_slice(&TSUInt::uint_to_range_no_overflow_field_limbs(
            $record.$timestamp + 1,
        ));
        $wire_values[UIntAddSub::<TSUInt>::carry_no_overflow_range(Self::$dst_slice().start)]
            .copy_from_slice(&UIntAddSub::<TSUInt>::compute_no_overflow_carries(
                $record.$timestamp,
                1,
            ));
    };
}

macro_rules! copy_stack_ts_add_from_record {
    ($wire_values: expr, $record: expr) => {
        copy_stack_memory_ts_add_from_record!(
            $wire_values,
            $record,
            phase0_stack_ts_add,
            stack_timestamp
        );
    };
}

macro_rules! copy_memory_ts_add_from_record {
    ($wire_values: expr, $record: expr) => {
        copy_stack_memory_ts_add_from_record!(
            $wire_values,
            $record,
            phase0_memory_ts_add,
            memory_timestamp
        );
    };
}

macro_rules! copy_stack_ts_lt_from_record {
    ($wire_values: expr, $record: expr, $stack_ts: tt, $stack_ts_lt: tt, $index: expr) => {
        copy_operand_timestamp_from_record!($wire_values, $record, $stack_ts, $index);

        $wire_values[UIntAddSub::<TSUInt>::carry_no_overflow_range(Self::$stack_ts_lt().start)]
            .copy_from_slice(&UIntAddSub::<TSUInt>::compute_no_overflow_borrows(
                $record.operands_timestamps[$index],
                $record.stack_timestamp,
            ));

        $wire_values
            [UIntAddSub::<TSUInt>::range_values_no_overflow_range(Self::$stack_ts_lt().start)]
        .copy_from_slice(&TSUInt::uint_to_range_no_overflow_field_limbs(
            $record.operands_timestamps[$index] + (1 << TSUInt::BIT_SIZE) - $record.stack_timestamp,
        ));
    };

    ($wire_values: expr, $record: expr, 0) => {
        copy_stack_ts_lt_from_record!(
            $wire_values,
            $record,
            phase0_old_stack_ts0,
            phase0_old_stack_ts_lt0,
            0
        );
    };

    ($wire_values: expr, $record: expr, 1) => {
        copy_stack_ts_lt_from_record!(
            $wire_values,
            $record,
            phase0_old_stack_ts1,
            phase0_old_stack_ts_lt1,
            1
        );
    };

    ($wire_values: expr, $record: expr) => {
        copy_stack_ts_lt_from_record!(
            $wire_values,
            $record,
            phase0_old_stack_ts,
            phase0_old_stack_ts_lt,
            0
        );
    };
}

macro_rules! copy_memory_ts_lt_from_record {
    ($wire_values: expr, $record: expr, $memory_ts: tt, $memory_ts_lt: tt, $timestamps_offset: expr, $num_mem_bytes: expr) => {
        for index in 0..$num_mem_bytes {
            copy_operand_timestamp_from_record!($wire_values, $record, $memory_ts, index);
            $wire_values[UIntAddSub::<TSUInt>::carry_no_overflow_range(
                Self::$memory_ts_lt().start + index * TSUInt::N_CARRY_NO_OVERFLOW_CELLS,
            )]
            .copy_from_slice(&UIntAddSub::<TSUInt>::compute_no_overflow_borrows(
                $record.operands_timestamps[index + $timestamps_offset],
                $record.memory_timestamp,
            ));

            $wire_values[UIntAddSub::<TSUInt>::range_values_no_overflow_range(
                Self::$memory_ts_lt().start + index * TSUInt::N_RANGE_CHECK_NO_OVERFLOW_CELLS,
            )]
            .copy_from_slice(&TSUInt::uint_to_range_no_overflow_field_limbs(
                $record.operands_timestamps[index + $timestamps_offset] + (1 << TSUInt::BIT_SIZE)
                    - $record.memory_timestamp,
            ));
        }
    };

    ($wire_values: expr, $record: expr, $timestamps_offset: expr) => {
        copy_memory_ts_lt_from_record!(
            $wire_values,
            $record,
            phase0_old_memory_ts,
            phase0_old_memory_ts_lt,
            $timestamps_offset,
            EVM_STACK_BYTE_WIDTH
        );
    };
}

macro_rules! copy_operand_from_record {
    ($wire_values: expr, $record: expr, $dst_slice: tt, $index: expr) => {
        $wire_values[Self::$dst_slice()]
            .copy_from_slice(&StackUInt::u256_to_field_elems($record.operands[$index]));
    };
}

macro_rules! copy_operand_single_cell_from_record {
    ($wire_values: expr, $record: expr, $dst_slice: tt, $index: expr) => {
        $wire_values[Self::$dst_slice()]
            .copy_from_slice(&StackUInt::u256_to_field_elems($record.operands[$index])[0..1]);
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
    ($wire_values: expr, $dst_slice: tt, $val: expr, $offset: expr) => {
        $wire_values[UIntAddSub::<StackUInt>::range_values_range(
            Self::$dst_slice().start + StackUInt::N_RANGE_CHECK_CELLS * $offset,
        )]
        .copy_from_slice(&StackUInt::u256_to_range_field_limbs($val));
    };

    ($wire_values: expr, $dst_slice: tt, $val: expr) => {
        copy_range_values_from_u256!($wire_values, $dst_slice, $val, 0);
    };
}

macro_rules! copy_carry_values_from_addends {
    ($wire_values: expr, $dst_slice: tt, $lval: expr, $rval: expr, $offset: expr) => {
        $wire_values[UIntAddSub::<StackUInt>::carry_range(
            Self::$dst_slice().start + StackUInt::N_CARRY_CELLS * $offset,
        )]
        .copy_from_slice(&UIntAddSub::<StackUInt>::compute_carries_u256($lval, $rval));
    };

    ($wire_values: expr, $dst_slice: tt, $lval: expr, $rval: expr) => {
        copy_carry_values_from_addends!($wire_values, $dst_slice, $lval, $rval, 0);
    };
}

macro_rules! copy_borrow_values_from_oprands {
    ($wire_values: expr, $dst_slice: tt, $lval: expr, $rval: expr) => {
        $wire_values[UIntAddSub::<StackUInt>::carry_range(Self::$dst_slice().start)]
            .copy_from_slice(&UIntAddSub::<StackUInt>::compute_borrows_u256($lval, $rval));
    };
}
