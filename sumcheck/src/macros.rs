#[macro_export]
macro_rules! entered_span {
    ($first:expr, $($fields:tt)*) => {
        $crate::tracing_span!($first, $($fields)*).entered()
    };
    ($first:expr $(,)*) => {
        $crate::tracing_span!($first).entered()
    };
}
#[macro_export]
macro_rules! tracing_span {
    ($first:expr, $($fields:tt)*) => {
        tracing::span!(tracing::Level::INFO, $first, $($fields)*)
    };
    ($first:expr $(,)*) => {
        tracing::span!(tracing::Level::INFO, $first)
    };
}
#[macro_export]
macro_rules! exit_span {
    ($first:expr $(,)*) => {
        $first.exit();
    };
}
