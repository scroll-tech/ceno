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

    pub fn is_first_shard(&self) -> bool {
        self.shard_id == 0
    }

    pub fn is_last_shard(&self) -> bool {
        self.shard_id == self.num_shards - 1
    }
}
