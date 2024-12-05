use tracing::span;

pub macro entered_span {
    ($first:expr $(, $($fields:tt)*)?) => {
        tracing_span!($first, $($($fields)*)?).entered()
    }
}

pub macro tracing_span {
    ($first:expr $(, $($fields:tt)*)?) => {
        span!(tracing::Level::TRACE, $first, $($($fields)*)?)
    },
}

pub macro exit_span($first:expr $(,)*) {
    $first.exit();
}
