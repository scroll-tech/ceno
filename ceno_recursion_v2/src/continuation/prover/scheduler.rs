use std::{
    fmt,
    ops::Range,
    sync::{Condvar, Mutex},
    time::Duration,
};

#[cfg(any(test, feature = "cuda"))]
use std::time::Instant;

use eyre::{Result, eyre};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RecursionNodeKind {
    Leaf,
    LeafBridge,
    Recursive { level: usize },
    Root,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct RecursionNodeId(pub usize);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RecursionNodeInput {
    BaseShard(usize),
    Node(RecursionNodeId),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RecursionNode {
    pub id: RecursionNodeId,
    pub kind: RecursionNodeKind,
    pub layer: usize,
    pub index: usize,
    pub shard_range: Range<usize>,
    pub children: Vec<RecursionNodeInput>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RecursionPlan {
    pub total_shards: usize,
    pub nodes: Vec<RecursionNode>,
    pub root: RecursionNodeId,
    parents: Vec<Option<RecursionNodeId>>,
    leaf_for_shard: Vec<RecursionNodeId>,
}

impl RecursionPlan {
    pub fn new(total_shards: usize, leaf_fanin: usize, internal_fanin: usize) -> Result<Self> {
        if total_shards == 0 {
            return Err(eyre!("recursion plan requires at least one base shard"));
        }
        if leaf_fanin == 0 {
            return Err(eyre!("leaf aggregation fanin must be non-zero"));
        }
        if internal_fanin == 0 {
            return Err(eyre!("internal aggregation fanin must be non-zero"));
        }

        let mut nodes = Vec::new();
        let mut leaf_for_shard = Vec::with_capacity(total_shards);
        let mut current = Vec::new();
        for (index, start) in (0..total_shards).step_by(leaf_fanin).enumerate() {
            let end = (start + leaf_fanin).min(total_shards);
            let id = push_node(
                &mut nodes,
                RecursionNodeKind::Leaf,
                0,
                index,
                start..end,
                (start..end).map(RecursionNodeInput::BaseShard).collect(),
            );
            leaf_for_shard.extend(std::iter::repeat_n(id, end - start));
            current.push(id);
        }

        current = push_parent_layer(
            &mut nodes,
            &current,
            internal_fanin,
            RecursionNodeKind::LeafBridge,
            1,
        );
        // Preserve the verifier's mandatory bridge and initial-recursive transcript layers even
        // when a partial tail means either layer has only one child.
        current = push_parent_layer(
            &mut nodes,
            &current,
            internal_fanin,
            RecursionNodeKind::Recursive { level: 0 },
            2,
        );
        let mut recursive_level = 1;
        while current.len() > 1 {
            current = push_parent_layer(
                &mut nodes,
                &current,
                internal_fanin,
                RecursionNodeKind::Recursive {
                    level: recursive_level,
                },
                2 + recursive_level,
            );
            recursive_level += 1;
        }

        let child = current[0];
        let child_range = nodes[child.0].shard_range.clone();
        let root = push_node(
            &mut nodes,
            RecursionNodeKind::Root,
            2 + recursive_level,
            0,
            child_range,
            vec![RecursionNodeInput::Node(child)],
        );
        let mut parents = vec![None; nodes.len()];
        for node in &nodes {
            for child in &node.children {
                if let RecursionNodeInput::Node(child) = child
                    && parents[child.0].replace(node.id).is_some()
                {
                    return Err(eyre!("recursion node {:?} has multiple parents", child));
                }
            }
        }

        Ok(Self {
            total_shards,
            nodes,
            root,
            parents,
            leaf_for_shard,
        })
    }

    pub fn parent(&self, node: RecursionNodeId) -> Option<RecursionNodeId> {
        self.parents[node.0]
    }

    pub fn leaf_for_shard(&self, shard_id: usize) -> Option<RecursionNodeId> {
        self.leaf_for_shard.get(shard_id).copied()
    }
}

fn push_node(
    nodes: &mut Vec<RecursionNode>,
    kind: RecursionNodeKind,
    layer: usize,
    index: usize,
    shard_range: Range<usize>,
    children: Vec<RecursionNodeInput>,
) -> RecursionNodeId {
    let id = RecursionNodeId(nodes.len());
    nodes.push(RecursionNode {
        id,
        kind,
        layer,
        index,
        shard_range,
        children,
    });
    id
}

fn push_parent_layer(
    nodes: &mut Vec<RecursionNode>,
    children: &[RecursionNodeId],
    fanin: usize,
    kind: RecursionNodeKind,
    layer: usize,
) -> Vec<RecursionNodeId> {
    children
        .chunks(fanin)
        .enumerate()
        .map(|(index, chunk)| {
            let start = nodes[chunk[0].0].shard_range.start;
            let end = nodes[chunk[chunk.len() - 1].0].shard_range.end;
            push_node(
                nodes,
                kind,
                layer,
                index,
                start..end,
                chunk
                    .iter()
                    .copied()
                    .map(RecursionNodeInput::Node)
                    .collect(),
            )
        })
        .collect()
}

#[derive(Debug)]
pub enum RecursionTask<B, P> {
    Leaf { node: RecursionNode, proofs: Vec<B> },
    Intermediate { node: RecursionNode, proofs: Vec<P> },
    Root { node: RecursionNode, proof: P },
}

impl<B, P> RecursionTask<B, P> {
    pub fn node(&self) -> &RecursionNode {
        match self {
            Self::Leaf { node, .. } | Self::Intermediate { node, .. } | Self::Root { node, .. } => {
                node
            }
        }
    }
}

#[derive(Debug)]
pub enum RecursionTaskResult<B, P, R> {
    Leaf {
        node: RecursionNodeId,
        proof: P,
        base_proofs: Vec<B>,
    },
    Intermediate {
        node: RecursionNodeId,
        proof: P,
    },
    Root {
        node: RecursionNodeId,
        proof: R,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum NodeStatus {
    Pending,
    Ready,
    Running,
    Complete,
}

struct SchedulerState<B, P, R> {
    base_proofs: Vec<Option<B>>,
    proofs: Vec<Option<P>>,
    root_proof: Option<R>,
    pending: Vec<usize>,
    status: Vec<NodeStatus>,
    ready: Vec<RecursionNodeId>,
    cancelled: Option<String>,
}

pub struct RecursionScheduler<B, P, R> {
    plan: RecursionPlan,
    state: Mutex<SchedulerState<B, P, R>>,
    changed: Condvar,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RecursionWorkerPhase {
    Wait,
    Execute,
    Complete,
    Teardown,
    Panic,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RecursionWorkerError {
    pub device_id: usize,
    pub node: Option<RecursionNodeId>,
    pub phase: RecursionWorkerPhase,
    pub message: String,
}

impl fmt::Display for RecursionWorkerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "recursion worker device {}", self.device_id)?;
        if let Some(node) = self.node {
            write!(f, " node {}", node.0)?;
        }
        write!(f, " {:?}: {}", self.phase, self.message)
    }
}

impl std::error::Error for RecursionWorkerError {}

#[derive(Clone, Debug, Default)]
pub struct RecursionWorkerMetrics {
    pub device_id: usize,
    pub task_count: usize,
    pub leaf_tasks: usize,
    pub leaf_bridge_tasks: usize,
    pub recursive_tasks: usize,
    pub root_tasks: usize,
    pub asset_hydrations: usize,
    pub asset_switches: usize,
    pub hydration_time: Duration,
    pub proving_time: Duration,
    pub total_time: Duration,
}

impl<B, P, R> RecursionScheduler<B, P, R> {
    pub fn new(plan: RecursionPlan) -> Self {
        let pending = plan.nodes.iter().map(|node| node.children.len()).collect();
        let node_count = plan.nodes.len();
        Self {
            state: Mutex::new(SchedulerState {
                base_proofs: (0..plan.total_shards).map(|_| None).collect(),
                proofs: (0..node_count).map(|_| None).collect(),
                root_proof: None,
                pending,
                status: vec![NodeStatus::Pending; node_count],
                ready: Vec::new(),
                cancelled: None,
            }),
            plan,
            changed: Condvar::new(),
        }
    }

    pub fn accept_base_proof(&self, shard_id: usize, proof: B) -> Result<()> {
        let leaf = self
            .plan
            .leaf_for_shard(shard_id)
            .ok_or_else(|| eyre!("out-of-range base proof shard {shard_id}"))?;
        let mut state = self.state.lock().unwrap();
        ensure_running(&state)?;
        if state.base_proofs[shard_id].is_some() {
            return Err(eyre!("duplicate base proof shard {shard_id}"));
        }
        state.base_proofs[shard_id] = Some(proof);
        decrement_and_enqueue(&mut state, leaf)?;
        self.changed.notify_all();
        Ok(())
    }

    pub fn wait_for_task(&self) -> Result<Option<RecursionTask<B, P>>> {
        let mut state = self.state.lock().unwrap();
        loop {
            ensure_running(&state)?;
            if let Some(id) = select_ready_node(&self.plan, &state.ready) {
                state.ready.retain(|candidate| *candidate != id);
                state.status[id.0] = NodeStatus::Running;
                return materialize_task(&self.plan, &mut state, id).map(Some);
            }
            if state.root_proof.is_some() {
                return Ok(None);
            }
            // The mutex closes the notification-before-wait race; completion/cancellation always
            // mutates state under the same lock before waking every eligible worker.
            state = self.changed.wait(state).unwrap();
        }
    }

    pub fn complete_task(&self, result: RecursionTaskResult<B, P, R>) -> Result<()> {
        let id = match &result {
            RecursionTaskResult::Leaf { node, .. }
            | RecursionTaskResult::Intermediate { node, .. }
            | RecursionTaskResult::Root { node, .. } => *node,
        };
        let mut state = self.state.lock().unwrap();
        ensure_running(&state)?;
        let Some(node) = self.plan.nodes.get(id.0) else {
            return self
                .fail_completion(&mut state, format!("out-of-range recursion node {}", id.0));
        };
        if state.status[id.0] != NodeStatus::Running {
            return self.fail_completion(
                &mut state,
                format!("recursion node {} completed while not running", id.0),
            );
        }

        match (&node.kind, &result) {
            (RecursionNodeKind::Leaf, RecursionTaskResult::Leaf { base_proofs, .. }) => {
                if base_proofs.len() != node.shard_range.len() {
                    return self.fail_completion(
                        &mut state,
                        format!(
                            "leaf node {} returned {} base proofs, expected {}",
                            id.0,
                            base_proofs.len(),
                            node.shard_range.len()
                        ),
                    );
                }
                if let Some(shard_id) = node
                    .shard_range
                    .clone()
                    .find(|shard_id| state.base_proofs[*shard_id].is_some())
                {
                    return self.fail_completion(
                        &mut state,
                        format!("leaf node {} returned duplicate shard {shard_id}", id.0),
                    );
                }
            }
            (RecursionNodeKind::Root, RecursionTaskResult::Root { .. }) => {}
            (RecursionNodeKind::Leaf, _) => {
                return self.fail_completion(
                    &mut state,
                    format!("leaf node {} returned the wrong result type", id.0),
                );
            }
            (RecursionNodeKind::Root, _) => {
                return self.fail_completion(
                    &mut state,
                    format!("root node {} returned the wrong result type", id.0),
                );
            }
            (_, RecursionTaskResult::Intermediate { .. }) => {}
            (_, _) => {
                return self.fail_completion(
                    &mut state,
                    format!("intermediate node {} returned the wrong result type", id.0),
                );
            }
        }
        if let Some(parent) = self.plan.parent(id)
            && state.pending[parent.0] == 0
        {
            return self.fail_completion(
                &mut state,
                format!("recursion node {} readiness underflow", parent.0),
            );
        }

        match result {
            RecursionTaskResult::Leaf {
                proof, base_proofs, ..
            } => {
                for (shard_id, proof) in node.shard_range.clone().zip(base_proofs) {
                    state.base_proofs[shard_id] = Some(proof);
                }
                state.proofs[id.0] = Some(proof);
            }
            RecursionTaskResult::Intermediate { proof, .. } => {
                state.proofs[id.0] = Some(proof);
            }
            RecursionTaskResult::Root { proof, .. } => state.root_proof = Some(proof),
        }
        state.status[id.0] = NodeStatus::Complete;
        if let Some(parent) = self.plan.parent(id) {
            decrement_and_enqueue(&mut state, parent)?;
        }
        self.changed.notify_all();
        Ok(())
    }

    fn fail_completion(&self, state: &mut SchedulerState<B, P, R>, error: String) -> Result<()> {
        if state.cancelled.is_none() {
            state.cancelled = Some(error.clone());
        }
        self.changed.notify_all();
        Err(eyre!(error))
    }

    pub fn cancel(&self, error: impl Into<String>) {
        let mut state = self.state.lock().unwrap();
        if state.cancelled.is_none() {
            state.cancelled = Some(error.into());
        }
        self.changed.notify_all();
    }

    pub fn cancellation_error(&self) -> Option<String> {
        self.state.lock().unwrap().cancelled.clone()
    }

    pub fn take_root_proof(&self) -> Result<Option<R>> {
        let mut state = self.state.lock().unwrap();
        ensure_running(&state)?;
        Ok(state.root_proof.take())
    }

    pub fn take_base_proofs(&self) -> Result<Vec<B>> {
        let mut state = self.state.lock().unwrap();
        ensure_running(&state)?;
        state
            .base_proofs
            .iter_mut()
            .enumerate()
            .map(|(shard_id, proof)| {
                proof
                    .take()
                    .ok_or_else(|| eyre!("base proof shard {shard_id} is not available"))
            })
            .collect()
    }
}

#[cfg(any(test, feature = "cuda"))]
pub(crate) fn run_scheduler_worker<B, P, R, Execute>(
    device_id: usize,
    scheduler: &RecursionScheduler<B, P, R>,
    mut execute: Execute,
) -> std::result::Result<RecursionWorkerMetrics, RecursionWorkerError>
where
    Execute: FnMut(
        RecursionTask<B, P>,
        &mut RecursionWorkerMetrics,
    ) -> Result<RecursionTaskResult<B, P, R>>,
{
    let started = Instant::now();
    let mut metrics = RecursionWorkerMetrics {
        device_id,
        ..Default::default()
    };
    loop {
        let task = match scheduler.wait_for_task() {
            Ok(Some(task)) => task,
            Ok(None) => {
                metrics.total_time = started.elapsed();
                return Ok(metrics);
            }
            Err(err) => {
                return Err(RecursionWorkerError {
                    device_id,
                    node: None,
                    phase: RecursionWorkerPhase::Wait,
                    message: err.to_string(),
                });
            }
        };
        let node = task.node().id;
        let kind = task.node().kind;
        let prove_started = Instant::now();
        let result = execute(task, &mut metrics).map_err(|err| RecursionWorkerError {
            device_id,
            node: Some(node),
            phase: RecursionWorkerPhase::Execute,
            message: err.to_string(),
        });
        metrics.proving_time += prove_started.elapsed();
        let result = match result {
            Ok(result) => result,
            Err(err) => {
                scheduler.cancel(err.to_string());
                return Err(err);
            }
        };
        if let Err(err) = scheduler.complete_task(result) {
            let err = RecursionWorkerError {
                device_id,
                node: Some(node),
                phase: RecursionWorkerPhase::Complete,
                message: err.to_string(),
            };
            scheduler.cancel(err.to_string());
            return Err(err);
        }
        metrics.task_count += 1;
        match kind {
            RecursionNodeKind::Leaf => metrics.leaf_tasks += 1,
            RecursionNodeKind::LeafBridge => metrics.leaf_bridge_tasks += 1,
            RecursionNodeKind::Recursive { .. } => metrics.recursive_tasks += 1,
            RecursionNodeKind::Root => metrics.root_tasks += 1,
        }
    }
}

fn ensure_running<B, P, R>(state: &SchedulerState<B, P, R>) -> Result<()> {
    match &state.cancelled {
        Some(error) => Err(eyre!(error.clone())),
        None => Ok(()),
    }
}

fn decrement_and_enqueue<B, P, R>(
    state: &mut SchedulerState<B, P, R>,
    node: RecursionNodeId,
) -> Result<()> {
    let pending = state
        .pending
        .get_mut(node.0)
        .ok_or_else(|| eyre!("out-of-range recursion node {}", node.0))?;
    if *pending == 0 {
        return Err(eyre!("recursion node {} readiness underflow", node.0));
    }
    *pending -= 1;
    if *pending == 0 {
        state.status[node.0] = NodeStatus::Ready;
        state.ready.push(node);
    }
    Ok(())
}

fn select_ready_node(plan: &RecursionPlan, ready: &[RecursionNodeId]) -> Option<RecursionNodeId> {
    // Prefer leaves, then a ready root, then the deepest intermediate; node index breaks ties.
    ready.iter().copied().min_by_key(|id| {
        let node = &plan.nodes[id.0];
        let class = match node.kind {
            RecursionNodeKind::Leaf => 0,
            RecursionNodeKind::Root => 1,
            _ => 2,
        };
        (class, usize::MAX - node.layer, node.index)
    })
}

fn materialize_task<B, P, R>(
    plan: &RecursionPlan,
    state: &mut SchedulerState<B, P, R>,
    id: RecursionNodeId,
) -> Result<RecursionTask<B, P>> {
    let node = plan.nodes[id.0].clone();
    match node.kind {
        RecursionNodeKind::Leaf => {
            let proofs = node
                .shard_range
                .clone()
                .map(|shard_id| {
                    state.base_proofs[shard_id]
                        .take()
                        .ok_or_else(|| eyre!("leaf node {} missing shard {shard_id}", id.0))
                })
                .collect::<Result<Vec<_>>>()?;
            Ok(RecursionTask::Leaf { node, proofs })
        }
        RecursionNodeKind::Root => {
            let [RecursionNodeInput::Node(child)] = node.children.as_slice() else {
                return Err(eyre!("root node {} must have one node child", id.0));
            };
            let proof = state.proofs[child.0]
                .take()
                .ok_or_else(|| eyre!("root node {} missing child {}", id.0, child.0))?;
            Ok(RecursionTask::Root { node, proof })
        }
        _ => {
            let proofs = node
                .children
                .iter()
                .map(|child| match child {
                    RecursionNodeInput::Node(child) => state.proofs[child.0]
                        .take()
                        .ok_or_else(|| eyre!("node {} missing child {}", id.0, child.0)),
                    RecursionNodeInput::BaseShard(shard_id) => Err(eyre!(
                        "intermediate node {} has base-shard child {shard_id}",
                        id.0
                    )),
                })
                .collect::<Result<Vec<_>>>()?;
            Ok(RecursionTask::Intermediate { node, proofs })
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{
        sync::{Arc, Barrier, mpsc},
        thread,
        time::Duration,
    };

    use super::*;

    fn finish_usize_task(
        scheduler: &RecursionScheduler<usize, usize, usize>,
        task: RecursionTask<usize, usize>,
    ) -> RecursionNodeKind {
        let kind = task.node().kind;
        let id = task.node().id;
        let result = match task {
            RecursionTask::Leaf { proofs, .. } => RecursionTaskResult::Leaf {
                node: id,
                proof: id.0,
                base_proofs: proofs,
            },
            RecursionTask::Intermediate { .. } => RecursionTaskResult::Intermediate {
                node: id,
                proof: id.0,
            },
            RecursionTask::Root { .. } => RecursionTaskResult::Root {
                node: id,
                proof: id.0,
            },
        };
        scheduler.complete_task(result).unwrap();
        kind
    }

    #[test]
    fn plan_preserves_mandatory_bridge_and_initial_recursive_layers() {
        let plan = RecursionPlan::new(1, 4, 4).unwrap();
        assert_eq!(plan.nodes.len(), 4);
        assert_eq!(plan.nodes[0].kind, RecursionNodeKind::Leaf);
        assert_eq!(plan.nodes[1].kind, RecursionNodeKind::LeafBridge);
        assert_eq!(
            plan.nodes[2].kind,
            RecursionNodeKind::Recursive { level: 0 }
        );
        assert_eq!(plan.nodes[3].kind, RecursionNodeKind::Root);
        assert_eq!(plan.nodes[3].shard_range, 0..1);
    }

    #[test]
    fn plan_keeps_partial_tails_and_consecutive_ranges() {
        let plan = RecursionPlan::new(11, 4, 4).unwrap();
        let leaves = plan
            .nodes
            .iter()
            .filter(|node| node.kind == RecursionNodeKind::Leaf)
            .collect::<Vec<_>>();
        assert_eq!(
            leaves
                .iter()
                .map(|node| node.shard_range.clone())
                .collect::<Vec<_>>(),
            vec![0..4, 4..8, 8..11]
        );
        assert_eq!(plan.nodes[plan.root.0].shard_range, 0..11);
    }

    #[test]
    fn invalid_plan_shapes_are_rejected() {
        assert!(RecursionPlan::new(0, 4, 4).is_err());
        assert!(RecursionPlan::new(1, 0, 4).is_err());
        assert!(RecursionPlan::new(1, 4, 0).is_err());
    }

    #[test]
    fn out_of_order_base_arrival_unlocks_only_complete_consecutive_leaf() {
        let scheduler =
            RecursionScheduler::<usize, usize, usize>::new(RecursionPlan::new(5, 2, 2).unwrap());
        scheduler.accept_base_proof(1, 1).unwrap();
        scheduler.accept_base_proof(2, 2).unwrap();
        scheduler.accept_base_proof(3, 3).unwrap();
        let task = scheduler.wait_for_task().unwrap().unwrap();
        assert_eq!(task.node().shard_range, 2..4);
        finish_usize_task(&scheduler, task);
        scheduler.accept_base_proof(0, 0).unwrap();
        let task = scheduler.wait_for_task().unwrap().unwrap();
        assert_eq!(task.node().shard_range, 0..2);
    }

    #[test]
    fn leaf_priority_is_non_preemptive_and_work_conserving() {
        let scheduler =
            RecursionScheduler::<usize, usize, usize>::new(RecursionPlan::new(3, 1, 2).unwrap());
        scheduler.accept_base_proof(0, 0).unwrap();
        let first = scheduler.wait_for_task().unwrap().unwrap();
        finish_usize_task(&scheduler, first);
        scheduler.accept_base_proof(1, 1).unwrap();
        let second = scheduler.wait_for_task().unwrap().unwrap();
        finish_usize_task(&scheduler, second);
        let bridge = scheduler.wait_for_task().unwrap().unwrap();
        assert_eq!(bridge.node().kind, RecursionNodeKind::LeafBridge);
        scheduler.accept_base_proof(2, 2).unwrap();
        finish_usize_task(&scheduler, bridge);
        let next = scheduler.wait_for_task().unwrap().unwrap();
        assert_eq!(next.node().kind, RecursionNodeKind::Leaf);
        assert_eq!(next.node().index, 2);
    }

    #[test]
    fn completion_immediately_unlocks_parent_and_reaches_root() {
        let scheduler =
            RecursionScheduler::<usize, usize, usize>::new(RecursionPlan::new(5, 2, 2).unwrap());
        for shard_id in 0..5 {
            scheduler.accept_base_proof(shard_id, shard_id).unwrap();
        }
        while scheduler.take_root_proof().unwrap().is_none() {
            let task = scheduler.wait_for_task().unwrap().unwrap();
            finish_usize_task(&scheduler, task);
        }
        assert_eq!(
            scheduler.take_base_proofs().unwrap(),
            (0..5).collect::<Vec<_>>()
        );
    }

    #[test]
    fn cancellation_wakes_a_blocked_worker_without_polling() {
        let scheduler = Arc::new(RecursionScheduler::<usize, usize, usize>::new(
            RecursionPlan::new(1, 1, 1).unwrap(),
        ));
        let worker = {
            let scheduler = scheduler.clone();
            thread::spawn(move || scheduler.wait_for_task().unwrap_err().to_string())
        };
        thread::sleep(Duration::from_millis(10));
        scheduler.cancel("forced failure");
        assert!(worker.join().unwrap().contains("forced failure"));
    }

    #[test]
    fn ready_notification_before_wait_is_not_lost() {
        let scheduler = Arc::new(RecursionScheduler::<usize, usize, usize>::new(
            RecursionPlan::new(1, 1, 1).unwrap(),
        ));
        scheduler.accept_base_proof(0, 7).unwrap();
        let (tx, rx) = mpsc::channel();
        let worker = {
            let scheduler = scheduler.clone();
            thread::spawn(move || {
                tx.send(scheduler.wait_for_task().unwrap().unwrap())
                    .unwrap()
            })
        };
        let task = rx.recv_timeout(Duration::from_secs(1)).unwrap();
        assert_eq!(task.node().kind, RecursionNodeKind::Leaf);
        worker.join().unwrap();
    }

    #[test]
    fn concurrent_workers_checkout_each_ready_task_exactly_once() {
        let scheduler = Arc::new(RecursionScheduler::<usize, usize, usize>::new(
            RecursionPlan::new(2, 1, 2).unwrap(),
        ));
        scheduler.accept_base_proof(0, 0).unwrap();
        scheduler.accept_base_proof(1, 1).unwrap();
        let barrier = Arc::new(Barrier::new(3));
        let workers = (0..2)
            .map(|_| {
                let scheduler = scheduler.clone();
                let barrier = barrier.clone();
                thread::spawn(move || {
                    barrier.wait();
                    scheduler.wait_for_task().unwrap().unwrap().node().id
                })
            })
            .collect::<Vec<_>>();
        barrier.wait();
        let mut checked_out = workers
            .into_iter()
            .map(|worker| worker.join().unwrap())
            .collect::<Vec<_>>();
        checked_out.sort_by_key(|id| id.0);
        checked_out.dedup();
        assert_eq!(checked_out.len(), 2);
    }

    #[test]
    fn fake_workers_complete_plan_and_report_structured_metrics() {
        let scheduler = Arc::new(RecursionScheduler::<usize, usize, usize>::new(
            RecursionPlan::new(5, 2, 2).unwrap(),
        ));
        for shard_id in 0..5 {
            scheduler.accept_base_proof(shard_id, shard_id).unwrap();
        }
        let node_count = scheduler.plan.nodes.len();
        let workers = (0..2)
            .map(|device_id| {
                let scheduler = scheduler.clone();
                thread::spawn(move || {
                    run_scheduler_worker(device_id, &scheduler, |task, _| {
                        let id = task.node().id;
                        Ok(match task {
                            RecursionTask::Leaf { proofs, .. } => RecursionTaskResult::Leaf {
                                node: id,
                                proof: id.0,
                                base_proofs: proofs,
                            },
                            RecursionTask::Intermediate { .. } => {
                                RecursionTaskResult::Intermediate {
                                    node: id,
                                    proof: id.0,
                                }
                            }
                            RecursionTask::Root { .. } => RecursionTaskResult::Root {
                                node: id,
                                proof: id.0,
                            },
                        })
                    })
                })
            })
            .collect::<Vec<_>>();
        let metrics = workers
            .into_iter()
            .map(|worker| worker.join().unwrap().unwrap())
            .collect::<Vec<_>>();
        assert_eq!(
            metrics
                .iter()
                .map(|metrics| metrics.task_count)
                .sum::<usize>(),
            node_count
        );
        assert_eq!(
            metrics
                .iter()
                .map(|metrics| metrics.root_tasks)
                .sum::<usize>(),
            1
        );
        assert!(scheduler.take_root_proof().unwrap().is_some());
        assert_eq!(
            scheduler.take_base_proofs().unwrap(),
            (0..5).collect::<Vec<_>>()
        );
    }

    #[test]
    fn one_fake_worker_uses_the_same_scheduler_to_completion() {
        let scheduler =
            RecursionScheduler::<usize, usize, usize>::new(RecursionPlan::new(5, 2, 2).unwrap());
        for shard_id in 0..5 {
            scheduler.accept_base_proof(shard_id, shard_id).unwrap();
        }
        let node_count = scheduler.plan.nodes.len();
        let metrics = run_scheduler_worker(0, &scheduler, |task, _| {
            let id = task.node().id;
            Ok(match task {
                RecursionTask::Leaf { proofs, .. } => RecursionTaskResult::Leaf {
                    node: id,
                    proof: id.0,
                    base_proofs: proofs,
                },
                RecursionTask::Intermediate { .. } => RecursionTaskResult::Intermediate {
                    node: id,
                    proof: id.0,
                },
                RecursionTask::Root { .. } => RecursionTaskResult::Root {
                    node: id,
                    proof: id.0,
                },
            })
        })
        .unwrap();
        assert_eq!(metrics.device_id, 0);
        assert_eq!(metrics.task_count, node_count);
        assert_eq!(metrics.root_tasks, 1);
        assert!(scheduler.take_root_proof().unwrap().is_some());
        assert_eq!(
            scheduler.take_base_proofs().unwrap(),
            (0..5).collect::<Vec<_>>()
        );
    }

    #[test]
    fn fake_worker_failure_cancels_and_wakes_peer() {
        let scheduler = Arc::new(RecursionScheduler::<usize, usize, usize>::new(
            RecursionPlan::new(1, 1, 1).unwrap(),
        ));
        scheduler.accept_base_proof(0, 0).unwrap();
        let barrier = Arc::new(Barrier::new(2));
        let (checked_out_tx, checked_out_rx) = mpsc::channel();
        let failing = {
            let scheduler = scheduler.clone();
            let barrier = barrier.clone();
            thread::spawn(move || {
                run_scheduler_worker(0, &scheduler, |_, _| {
                    checked_out_tx.send(()).unwrap();
                    barrier.wait();
                    Err(eyre!("injected failure"))
                })
            })
        };
        checked_out_rx.recv_timeout(Duration::from_secs(1)).unwrap();
        let waiting = {
            let scheduler = scheduler.clone();
            thread::spawn(move || run_scheduler_worker(1, &scheduler, |_, _| unreachable!()))
        };
        barrier.wait();
        let errors = [waiting.join().unwrap(), failing.join().unwrap()]
            .into_iter()
            .map(|result| result.unwrap_err().to_string())
            .collect::<Vec<_>>();
        assert!(
            scheduler
                .cancellation_error()
                .unwrap()
                .contains("injected failure")
        );
        assert!(
            errors
                .iter()
                .all(|error| error.contains("injected failure"))
        );
    }

    #[test]
    fn duplicates_and_wrong_results_are_rejected() {
        let scheduler =
            RecursionScheduler::<usize, usize, usize>::new(RecursionPlan::new(1, 1, 1).unwrap());
        scheduler.accept_base_proof(0, 0).unwrap();
        assert!(scheduler.accept_base_proof(0, 1).is_err());
        let task = scheduler.wait_for_task().unwrap().unwrap();
        let RecursionTask::Leaf { proofs, .. } = &task else {
            panic!("expected leaf task");
        };
        assert_eq!(proofs, &[0]);
        let id = task.node().id;
        let error = scheduler
            .complete_task(RecursionTaskResult::Intermediate { node: id, proof: 0 })
            .unwrap_err()
            .to_string();
        assert!(error.contains("wrong result type"));
        assert!(
            scheduler
                .wait_for_task()
                .unwrap_err()
                .to_string()
                .contains(&error)
        );
    }
}
