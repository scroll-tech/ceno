# Memory Continuation Checks

When execution is split into multiple shards, Ceno must check not only
that control flow continues correctly, but also that the dynamic memory
regions exposed through public values remain consistent across shard
boundaries.

The two dynamic regions are:

- **Heap**
- **Hints**

Each shard exposes the start address and length of its current heap and
hint segment. The verifier then checks that these segments form one
continuous sequence over the full trace.

Intuitively, this supports lazy dynamic init: early shards can expose
zero length for heap/hints, and the segment only extends once those
addresses are first accessed. Because every next segment must start at
the previous end, the exposed ranges are append-only and non-overlapping,
so an address cannot be initialized twice across shards.

<p align="center">

```text
heap / hint address space

 shard 0             shard 1             shard 2
┌──────────────┐    ┌──────────────┐    ┌──────────────┐
│ start = s0   │    │ start = e0   │    │ start = e1   │
│ len   = l0   │    │ len   = l1   │    │ len   = l2   │
│ end   = e0   │───▶│ end   = e1   │───▶│ end   = e2   │
└──────────────┘    └──────────────┘    └──────────────┘

Requirements:
- every start/end stays inside the allowed platform range
- next shard starts exactly at previous shard end
- segments are append-only (no overlaps or rewinds)
- proof table length matches the public length
```

</p>

## What Is Being Checked

For both heap and hints, full-trace verification enforces:

- **Range correctness**: each shard's start and end must stay inside the
  configured memory window
- **Continuation**: shard `i + 1` must start exactly where shard `i`
  ended
- **Length consistency**: the dynamic init table proved inside the shard
  must have the same length as the public value

These checks rule out three classes of errors:

- a shard claiming memory outside the allowed heap or hint range
- a gap or overlap between consecutive shards
- a mismatch between the public memory length and the table actually
  proved

## How This Fits with the Other Memory Checks

These continuation checks are different from the cross-shard RAM
consistency check.

- **RAM consistency** checks that reads and writes across shards compose
  to one valid memory history
- **Memory continuation** checks that the dynamic heap and hint segments
  themselves are chained correctly from shard to shard

Both are needed:

- RAM consistency protects the memory contents
- continuation checks protect the public memory layout

## Full-Trace vs Single-Shard Verification

Continuation is a **full-trace** property.

- In full-trace verification, heap and hint segments are chained across
  all shards
- In single-shard debug verification, Ceno only checks that the selected
  shard is internally valid; it does not claim that the shard forms a
  complete continuation of the whole execution

## Where This Lives in the System

- the platform defines the allowed heap and hint ranges
- the native verifier checks shard-by-shard continuation
- the recursion verifier enforces the same bounds in aggregation

This keeps the memory-state invariant aligned across both native and
recursive verification.
