#[macro_export]
macro_rules! vec_mut {
    ($a:ident, |$tmp_a:ident| $op:expr) => {
        match $a {
            multilinear_extensions::mle::FieldType::Base(ref mut $tmp_a) => $op,
            multilinear_extensions::mle::FieldType::Ext(ref mut $tmp_a) => $op,
            _ => unreachable!(),
        }
    };
    (|$a:ident| $op:expr) => {
        vec_mut!($a, |$a| $op)
    };
}

#[macro_export]
macro_rules! vec_map {
    ($a:ident, |$tmp_a:ident| $op:expr) => {
        match &$a {
            multilinear_extensions::mle::FieldType::Base(a) => {
                let $tmp_a = &a[..];
                let out = $op;
                multilinear_extensions::mle::FieldType::Base(out)
            }
            multilinear_extensions::mle::FieldType::Ext(a) => {
                let $tmp_a = &a[..];
                let out = $op;
                multilinear_extensions::mle::FieldType::Base(out)
            }
            _ => unreachable!(),
        }
    };
    (|$a:ident| $op:expr) => {
        vec_map!($a, |$a| $op)
    };
}
