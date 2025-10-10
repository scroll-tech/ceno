pub struct Shards {
    pub shard_id: usize,
    pub num_shards: usize,
}

impl Shards {
    pub fn new(shard_id: usize, num_shards: usize) -> Self {
        assert!(shard_id < num_shards);
        Self {
            shard_id,
            num_shards,
        }
    }
}
