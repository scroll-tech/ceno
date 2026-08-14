#!/usr/bin/env python3
"""Summarize kernel overlap for scheduler-owned CUDA streams in an Nsight SQLite export."""

from __future__ import annotations

import argparse
import sqlite3
from collections import defaultdict
from pathlib import Path


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Report CUDA kernel time and overlap for scheduler stream IDs."
    )
    parser.add_argument("report", type=Path, help="SQLite file exported by nsys")
    parser.add_argument(
        "stream_ids", type=int, nargs="+", metavar="STREAM_ID", help="scheduler CUDA stream IDs"
    )
    return parser.parse_args()


def milliseconds(nanoseconds: int) -> float:
    return nanoseconds / 1_000_000.0


def main() -> None:
    args = parse_args()
    stream_ids = list(dict.fromkeys(args.stream_ids))
    if len(stream_ids) != len(args.stream_ids):
        raise SystemExit("scheduler stream IDs must be unique")

    placeholders = ",".join("?" for _ in stream_ids)
    query = f"""
        SELECT streamId, start, end
        FROM CUPTI_ACTIVITY_KIND_KERNEL
        WHERE streamId IN ({placeholders})
        ORDER BY start, end
    """
    try:
        with sqlite3.connect(f"file:{args.report}?mode=ro", uri=True) as database:
            rows = database.execute(query, stream_ids).fetchall()
    except sqlite3.Error as error:
        raise SystemExit(f"failed to read Nsight SQLite report: {error}") from error

    if not rows:
        raise SystemExit("no CUDA kernels found for the requested scheduler stream IDs")

    per_stream: dict[int, list[int]] = {stream_id: [0, 0] for stream_id in stream_ids}
    changes: dict[int, int] = defaultdict(int)
    wall_start = rows[0][1]
    wall_end = rows[0][2]
    for stream_id, start, end in rows:
        per_stream[stream_id][0] += 1
        per_stream[stream_id][1] += end - start
        changes[start] += 1
        changes[end] -= 1
        wall_start = min(wall_start, start)
        wall_end = max(wall_end, end)

    active_kernels = 0
    overlap = 0
    simultaneous = 0
    maximum_simultaneous = 0
    previous = wall_start
    for timestamp in sorted(changes):
        duration = timestamp - previous
        if simultaneous >= 1:
            active_kernels += duration
        if simultaneous >= 2:
            overlap += duration
        simultaneous += changes[timestamp]
        maximum_simultaneous = max(maximum_simultaneous, simultaneous)
        previous = timestamp

    wall = wall_end - wall_start
    print(f"report: {args.report}")
    for stream_id in stream_ids:
        count, kernel_time = per_stream[stream_id]
        print(
            f"stream {stream_id}: kernels={count}, kernel_time_ms={milliseconds(kernel_time):.3f}"
        )
    print(f"scheduler_wall_interval_ms: {milliseconds(wall):.3f}")
    print(f"active_kernel_time_ms: {milliseconds(active_kernels):.3f}")
    print(f"overlap_time_ms: {milliseconds(overlap):.3f}")
    print(f"overlap_percent_of_wall: {100.0 * overlap / wall:.2f}%")
    print(f"maximum_simultaneous_kernels: {maximum_simultaneous}")


if __name__ == "__main__":
    main()
