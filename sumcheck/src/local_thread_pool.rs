use std::sync::{Arc, Once};

use rayon::ThreadPool;

pub(crate) static mut LOCAL_THREAD_POOL: Option<Arc<ThreadPool>> = None;
static LOCAL_THREAD_POOL_SET: Once = Once::new();

pub fn create_local_pool_once(size: usize, in_place: bool) {
    unsafe {
        let size = if in_place { size - 1 } else { size };
        let pool_size = LOCAL_THREAD_POOL
            .as_ref()
            .map(|a| a.current_num_threads())
            .unwrap_or(0);
        if pool_size > 0 && pool_size != size {
            panic!(
                "calling prove_batch_polys with different polys size. prev size {} vs now size {}",
                pool_size, size
            );
        }
        LOCAL_THREAD_POOL_SET.call_once(|| {
            let _ = Some(&*LOCAL_THREAD_POOL.get_or_insert_with(|| {
                Arc::new(
                    rayon::ThreadPoolBuilder::new()
                        .num_threads(size)
                        .build()
                        .unwrap(),
                )
            }));
        });
    }
}
