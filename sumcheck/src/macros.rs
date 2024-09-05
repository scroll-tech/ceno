#[macro_export]
macro_rules! entered_span {
    ($first:expr $(,)*) => {
        tracing::debug_span!($first).entered()
    };
}

#[macro_export]
macro_rules! exit_span {
    ($first:expr $(,)*) => {
        $first.exit();
    };
}
