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
//             let ($wire_name, $name) = $builder.create_witness_in($length);
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
