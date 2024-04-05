use ark_std::perf_trace::TimerInfo;
use tracing::span::EnteredSpan;

pub(crate) struct TracingTimer {
    pub tracing_timer: TimerInfo,
    pub span: EnteredSpan,
}

#[macro_export]
macro_rules! start_timer {
    ($msg:expr) => {{
        use crate::macros::TracingTimer;
        use ark_std::start_timer as ark_start_timer;
        use tracing::info_span;
        TracingTimer {
            tracing_timer: ark_start_timer! {|| format!{"{}", msg}},
            span: info_span! {$msg}.entered(),
        }
    }};
    ($msg1:expr, $msg2:expr) => {{
        use crate::macros::TracingTimer;
        use ark_std::start_timer as ark_start_timer;
        use tracing::info_span;
        TracingTimer {
            tracing_timer: ark_start_timer! {|| format!("{} {}", $msg1, $msg2)},
            span: info_span! {$msg1, $msg2}.entered(),
        }
    }};
    ($msg1:expr, $msg2:expr, $msg3:expr) => {{
        use crate::macros::TracingTimer;
        use ark_std::start_timer as ark_start_timer;
        use tracing::info_span;
        TracingTimer {
            tracing_timer: ark_start_timer! {|| format!("{}, {}, {}",$msg1, $msg2, $msg3)},
            span: info_span! {$msg1, $msg2, $msg3}.entered(),
        }
    }};
}

#[macro_export]
macro_rules! end_timer {
    ($msg:expr) => {{
        use ark_std::end_timer as ark_end_timer;
        ark_end_timer! {$msg.tracing_timer};
        $msg.span.exit();
    }};
}
