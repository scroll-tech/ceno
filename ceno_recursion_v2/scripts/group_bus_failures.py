#!/usr/bin/env python3
"""Group Stark interaction-bus balance failures by bus id.

Usage:
    python3 scripts/group_bus_failures.py prover.log
    cargo ... 2>&1 | python3 scripts/group_bus_failures.py
"""

from __future__ import annotations

import argparse
import re
import sys
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from pathlib import Path


BABYBEAR_MODULUS = 2_013_265_921

BUS_NAMES = {
    0: "TranscriptBus",
    1: "Poseidon2PermuteBus",
    2: "Poseidon2CompressBus",
    3: "MerkleVerifyBus",
    4: "TowerModuleBus",
    5: "AirShapeBus",
    6: "HyperdimBus",
    7: "LiftedHeightsBus",
    8: "PublicValuesBus",
    9: "RangeCheckerBus",
    10: "PowerCheckerBus",
    11: "ExpressionClaimNMaxBus",
    12: "FractionFolderInputBus",
    13: "NLiftBus",
    14: "XiRandomnessBus",
    15: "ExpBitsLenBus",
    16: "RightShiftBus",
    17: "MainBus",
    18: "MainSumcheckInputBus",
    19: "MainSumcheckOutputBus",
    20: "MainExpressionClaimBus",
    21: "CachedCommitBus",
    22: "FinalTranscriptStateBus",
    23: "ForkedTranscriptBus",
    24: "LookupChallengeBus",
    25: "ProofShapePermutationBus",
    26: "StartingTidxBus",
    27: "NumPublicValuesBus",
    28: "TowerLayerInputBus",
    29: "TowerLayerOutputBus",
    30: "TowerSumcheckInputBus",
    31: "TowerSumcheckOutputBus",
    32: "TowerSumcheckChallengeBus",
    33: "TowerProdReadClaimInputBus",
    34: "TowerProdReadClaimBus",
    35: "TowerProdWriteClaimInputBus",
    36: "TowerProdWriteClaimBus",
    37: "TowerLogupClaimInputBus",
    38: "TowerLogupClaimBus",
    39: "AirPresenceBus",
    40: "ColumnClaimsBus",
    41: "SelHypercubeBus",
    42: "SelUniBus",
    43: "BatchConstraintConductorBus",
    44: "EqNOuterBus",
    45: "SymbolicExpressionBus",
    46: "ExpressionClaimBus",
    47: "InteractionsFoldingBus",
    48: "ConstraintsFoldingBus",
    49: "PvsAirConsistencyBus",
}

FAILURE_RE = re.compile(
    r"Bus\s+(?P<bus>\d+)\s+failed to balance .*?fields=(?P<fields>\[[^\]]*\])"
)
CONNECTION_RE = re.compile(
    r"Air idx:\s*(?P<air_idx>\d+),\s*Air name:\s*(?P<air_name>.*?),\s*count:\s*(?P<count>\d+)"
)


@dataclass(frozen=True)
class Connection:
    air_idx: int
    air_name: str
    raw_count: int
    signed_count: int

    @property
    def role(self) -> str:
        if self.signed_count > 0:
            return "send"
        if self.signed_count < 0:
            return "receive"
        return "disabled"


@dataclass
class Failure:
    bus: int
    fields: str
    connections: list[Connection] = field(default_factory=list)


def decode_field(value: int, modulus: int) -> int:
    if value > modulus // 2:
        return value - modulus
    return value


def read_lines(paths: list[Path]) -> list[str]:
    if not paths:
        return sys.stdin.read().splitlines()
    lines: list[str] = []
    for path in paths:
        lines.extend(path.read_text().splitlines())
    return lines


def parse_failures(lines: list[str], modulus: int) -> list[Failure]:
    failures: list[Failure] = []
    current: Failure | None = None

    for line in lines:
        failure_match = FAILURE_RE.search(line)
        if failure_match:
            current = Failure(
                bus=int(failure_match.group("bus")),
                fields=failure_match.group("fields"),
            )
            failures.append(current)
            continue

        connection_match = CONNECTION_RE.search(line)
        if connection_match and current is not None:
            raw_count = int(connection_match.group("count"))
            current.connections.append(
                Connection(
                    air_idx=int(connection_match.group("air_idx")),
                    air_name=connection_match.group("air_name").strip(),
                    raw_count=raw_count,
                    signed_count=decode_field(raw_count, modulus),
                )
            )

    return failures


def print_summary(failures: list[Failure]) -> None:
    by_bus: dict[int, list[Failure]] = defaultdict(list)
    for failure in failures:
        by_bus[failure.bus].append(failure)

    if not by_bus:
        print("No bus balance failures found.")
        return

    for bus in sorted(by_bus):
        bus_failures = by_bus[bus]
        bus_name = BUS_NAMES.get(bus, "unknown")
        print(f"Bus {bus} ({bus_name}): {len(bus_failures)} failure(s)")

        by_fields: dict[str, list[Failure]] = defaultdict(list)
        for failure in bus_failures:
            by_fields[failure.fields].append(failure)

        for fields, field_failures in sorted(
            by_fields.items(), key=lambda item: (-len(item[1]), item[0])
        ):
            connection_counter: Counter[Connection] = Counter()
            imbalance = 0
            for failure in field_failures:
                for connection in failure.connections:
                    connection_counter[connection] += 1
                    imbalance += connection.signed_count

            print(f"  fields={fields}")
            print(f"    occurrences: {len(field_failures)}")
            print(f"    signed imbalance from listed connections: {imbalance}")

            if not connection_counter:
                print("    connections: none listed")
                continue

            print("    connections:")
            for connection, occurrences in sorted(
                connection_counter.items(),
                key=lambda item: (
                    item[0].air_idx,
                    item[0].air_name,
                    item[0].signed_count,
                    item[0].raw_count,
                ),
            ):
                print(
                    "      "
                    f"{connection.role:7s} "
                    f"air={connection.air_idx} "
                    f"name={connection.air_name} "
                    f"count={connection.signed_count} "
                    f"raw={connection.raw_count} "
                    f"occurrences={occurrences}"
                )
        print()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("logs", nargs="*", type=Path, help="Log files. Reads stdin when omitted.")
    parser.add_argument(
        "--modulus",
        type=int,
        default=BABYBEAR_MODULUS,
        help="Field modulus used to decode negative counts.",
    )
    args = parser.parse_args()

    failures = parse_failures(read_lines(args.logs), args.modulus)
    print_summary(failures)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
