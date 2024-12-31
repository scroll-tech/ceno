#[macro_export]
macro_rules! op_by_type {
    ($ele_type:ident, $ele:ident, |$x:ident| $op:expr, |$y_ext:ident| $convert_ext:expr, |$y_base:ident| $convert_base:expr) => {
        match $ele {
            $ele_type::Base($x) => {
                let $y_base = $op;
                $convert_base
            }
            $ele_type::Ext($x) => {
                let $y_ext = $op;
                $convert_ext
            }
        }
    };

    ($ele_type:ident, $ele:ident, |$x:ident| $op:expr, |$y_base:ident| $convert_base:expr) => {
        match $ele {
            $ele_type::Base($x) => {
                let $y_base = $op;
                $convert_base
            }
            $ele_type::Ext($x) => $op,
        }
    };

    ($ele_type:ident, $ele:ident, |$x:ident| $op:expr) => {
        match $ele {
            $ele_type::Base($x) => $op,
            $ele_type::Ext($x) => $op,
        }
    };
}

#[macro_export]
macro_rules! define_commutative_op_mle2 {
    ($ele_type:ident, $trait_type:ident, $func_type:ident, |$x:ident, $y:ident| $op:expr) => {
        impl<E: ExtensionField> $trait_type for $ele_type<E> {
            type Output = Self;

            fn $func_type(self, other: Self) -> Self::Output {
                #[allow(unused)]
                match (self, other) {
                    ($ele_type::Base(mut $x), $ele_type::Base($y)) => $ele_type::Base($op),
                    ($ele_type::Ext(mut $x), $ele_type::Base($y))
                    | ($ele_type::Base($y), $ele_type::Ext(mut $x)) => $ele_type::Ext($op),
                    ($ele_type::Ext(mut $x), $ele_type::Ext($y)) => $ele_type::Ext($op),
                }
            }
        }

        impl<'a, E: ExtensionField> $trait_type<&'a Self> for $ele_type<E> {
            type Output = Self;

            fn $func_type(self, other: &'a Self) -> Self::Output {
                #[allow(unused)]
                match (self, other) {
                    ($ele_type::Base(mut $x), $ele_type::Base($y)) => $ele_type::Base($op),
                    ($ele_type::Ext(mut $x), $ele_type::Base($y)) => $ele_type::Ext($op),
                    ($ele_type::Base($y), $ele_type::Ext($x)) => {
                        let mut $x = $x.clone();
                        $ele_type::Ext($op)
                    }
                    ($ele_type::Ext(mut $x), $ele_type::Ext($y)) => $ele_type::Ext($op),
                }
            }
        }
    };
}

#[macro_export]
macro_rules! define_op_mle2 {
    ($ele_type:ident, $trait_type:ident, $func_type:ident, |$x:ident, $y:ident| $op:expr) => {
        impl<E: ExtensionField> $trait_type for $ele_type<E> {
            type Output = Self;

            fn $func_type(self, other: Self) -> Self::Output {
                let $x = self;
                let $y = other;
                $op
            }
        }
    };
}

#[macro_export]
macro_rules! define_op_mle {
    ($ele_type:ident, $trait_type:ident, $func_type:ident, |$x:ident| $op:expr) => {
        impl<E: ExtensionField> $trait_type for $ele_type<E> {
            type Output = Self;

            fn $func_type(self) -> Self::Output {
                #[allow(unused)]
                match (self) {
                    $ele_type::Base(mut $x) => $ele_type::Base($op),
                    $ele_type::Ext(mut $x) => $ele_type::Ext($op),
                }
            }
        }
    };
}
