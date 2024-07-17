#[macro_export]
macro_rules! register_witness {
    // phaseX_size() implementation
    ($struct_name:ident, $($wire_name:ident { $($slice_name:ident => $length:expr),* }),*) => {
        paste! {
            impl $struct_name {
                $(
                    #[inline]
                    pub fn [<$wire_name _ size>]() -> usize {
                        (0 $(+ $length)* as usize).next_power_of_two()
                    }

                    register_witness!(@internal $wire_name, 0usize; $($slice_name => $length),*);

                    #[inline]
                    pub fn [<$wire_name _ idxes_map>]() -> BTreeMap<&'static str, std::ops::Range<usize>> {
                        let mut map = BTreeMap::new();

                        $(
                            map.insert(stringify!([<$wire_name _ $slice_name>]), Self::[<$wire_name _ $slice_name>]());
                        )*

                        map
                    }

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

                    #[inline]
                    pub fn [<$wire_name _ idxes_map>]() -> BTreeMap<&'static str, std::ops::Range<usize>> {
                        let mut map = BTreeMap::new();

                        $(
                            map.insert(stringify!([<$wire_name _ $slice_name>]), Self::[<$wire_name _ $slice_name>]());
                        )*

                        map
                    }

                )*
            }
        }
    };

    (@internal $wire_name:ident, $offset:expr; $name:ident => $length:expr $(, $rest:ident => $rest_length:expr)*) => {
        paste! {
            pub fn [<$wire_name _ $name>]() -> std::ops::Range<usize> {
                $offset..$offset + $length
            }

            pub fn [<$wire_name _ $name _ str>]() -> &'static str {
                stringify!([<$wire_name _ $name>])
            }
            register_witness!(@internal $wire_name, $offset + $length; $($rest => $rest_length),*);
        }
    };

    (@internal $wire_name:ident, $offset:expr;) => {};
}

#[macro_export]
macro_rules! register_multi_witness {
    ($struct_name:ident, $($wire_name:ident($($wire_param:ident)*) { $($slice_name:ident$(($num:expr))? => $length:expr),* }),*) => {
        paste! {
            impl $struct_name {
                $(
                    register_multi_witness!(@internal $wire_name($($wire_param)*), 0usize; $($slice_name$(($num))? => $length),*);
                )*
            }
        }
    };

    ($struct_name:ident<N>, $($wire_name:ident($($wire_param:ident)*) { $($slice_name:ident$(($num:expr))? => $length:expr),* }),*) => {
        paste! {
            impl<const N: usize> $struct_name<N> {
                $(
                    register_multi_witness!(@internal $wire_name($($wire_param)*), 0usize; $($slice_name$(($num))? => $length),*);
                )*
            }
        }
    };

    (@internal $wire_name:ident($($wire_param:ident)*), $offset:expr; $name:ident($num:expr) => $length:expr $(, $rest:ident$(($rest_num:expr))? => $rest_length:expr)*) => {
        paste! {
            #[inline]
            pub fn [<$wire_name _ $name>](idx: usize$(, $wire_param: usize)*) -> std::ops::Range<usize> {
                $offset + $length * idx..$offset + $length * (idx + 1)
            }
            register_multi_witness!(@internal $wire_name($($wire_param)*), $offset + $length * $num; $($rest$(($rest_num))? => $rest_length),*);
        }
    };

    (@internal $wire_name:ident($($wire_param:ident)*), $offset:expr; $name:ident => $length:expr $(, $rest:ident$(($rest_num:expr))? => $rest_length:expr)*) => {
        paste! {
            #[inline]
            pub fn [<$wire_name _ $name>]($($wire_param: usize)*) -> std::ops::Range<usize> {
                $offset..$offset + $length
            }
            register_multi_witness!(@internal $wire_name($($wire_param)*), $offset + $length; $($rest$(($rest_num))? => $rest_length),*);
        }
    };

    (@internal $wire_name:ident($($wire_param:ident)*), $offset:expr;) => {
        paste! {
            #[inline]
            pub fn [<$wire_name _ size>]($($wire_param: usize)*) -> usize {
                $offset.next_power_of_two()
            }
        }
    };
}
