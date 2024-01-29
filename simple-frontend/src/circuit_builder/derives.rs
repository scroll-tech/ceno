#[macro_export]
macro_rules! rlc_const_term {
    ($builder:ident, $n_ext:expr, $out:expr; $c:expr) => {
        for j in 0..$n_ext {
            $builder.add_const_internal($out[j], ConstantType::Challenge($c, j));
        }
    };
    ($builder:ident, $n_ext:expr, $out:expr; $c:expr, $scalar:expr) => {
        for j in 0..$n_ext {
            $builder.add_const_internal($out[j], ConstantType::ChallengeScaled($c, j, $scalar));
        }
    };
}
#[macro_export]
macro_rules! rlc_base_term {
    ($builder:ident, $n_ext:expr, $out:expr, $in_0:expr; $c:expr) => {
        for j in 0..$n_ext {
            $builder.add_internal($out[j], $in_0, ConstantType::Challenge($c, j));
        }
    };
    ($builder:ident, $n_ext:expr, $out:expr, $in_0:expr; $c:expr, $scalar:expr) => {
        for j in 0..$n_ext {
            $builder.add_internal(
                $out[j],
                $in_0,
                ConstantType::ChallengeScaled($c, j, $scalar),
            );
        }
    };
}
