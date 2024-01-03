#[cfg(feature = "timer")]
pub use enabled::{end_timer, start_timer, start_unit_timer};

#[cfg(not(feature = "timer"))]
pub use disabled::{end_timer, start_timer, start_unit_timer};

#[cfg(feature = "timer")]
mod enabled {
    use ark_std::{end_timer, perf_trace::TimerInfo as InnerTimerInfo, start_timer};
    use std::sync::atomic::{AtomicBool, Ordering};

    static IN_UNIT: AtomicBool = AtomicBool::new(false);

    pub struct TimerInfo {
        pub inner: Option<InnerTimerInfo>,
        unit: bool,
    }

    pub fn start_timer<T: ToString>(_msg: impl Fn() -> T) -> TimerInfo {
        TimerInfo {
            inner: (!IN_UNIT.load(Ordering::Relaxed)).then(|| start_timer!(|| _msg().to_string())),
            unit: false,
        }
    }

    pub fn start_unit_timer<T: ToString>(_msg: impl Fn() -> T) -> TimerInfo {
        if IN_UNIT
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |_| Some(true))
            .unwrap()
        {
            panic!("Unit timer should not be nested");
        }
        TimerInfo {
            inner: Some(start_timer!(|| _msg().to_string())),
            unit: true,
        }
    }

    pub fn end_timer(mut info: TimerInfo) {
        end_timer_inner(&mut info);
    }

    impl Drop for TimerInfo {
        fn drop(&mut self) {
            end_timer_inner(self);
        }
    }

    fn end_timer_inner(info: &mut TimerInfo) {
        if let Some(inner) = info.inner.take() {
            end_timer!(inner);
            if info.unit {
                IN_UNIT
                    .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |_| Some(false))
                    .unwrap();
            }
        }
    }
}

#[cfg(not(feature = "timer"))]
mod disabled {
    pub struct TimerInfo;

    pub fn start_timer<T: ToString>(_: impl Fn() -> T) -> TimerInfo {
        TimerInfo
    }

    pub fn start_unit_timer<T: ToString>(_: impl Fn() -> T) -> TimerInfo {
        TimerInfo
    }

    pub fn end_timer(_: TimerInfo) {}
}
