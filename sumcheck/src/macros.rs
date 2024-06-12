#[macro_export]
macro_rules! entered_span {
    ($first:expr $(,)*) => {
        $crate::tracing_span!($first).entered()
    };
}

#[macro_export]
macro_rules! tracing_span {
    ($first:expr $(,)*) => {
        tracing::span!(tracing::Level::DEBUG, $first)
    };
}

#[macro_export]
macro_rules! exit_span {
    ($first:expr $(,)*) => {
        $first.exit();
    };
}
