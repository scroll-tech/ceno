use tracing::span;

pub macro entered_span {
    ($first:expr, $($fields:tt)*) => {
        tracing_span!($first, $($fields)*).entered()
    },
    ($first:expr $(,)*) => {
        tracing_span!($first).entered()
    },
}

pub macro tracing_span {
    ($first:expr, $($fields:tt)*) => {
        span!(tracing::Level::INFO, $first, $($fields)*)
    },
    ($first:expr $(,)*) => {
        span!(tracing::Level::INFO, $first)
    },
}

pub macro exit_span($first:expr $(,)*) {
    $first.exit();
}
