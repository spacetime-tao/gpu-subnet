"""Map a signed report to raw relative weights at a trusted roster snapshot."""

from dataclasses import dataclass

from .evidence import (
    ReportError,
    WorkReport,
    _chain_hash,
    _fields,
    _hotkey,
    _read_json,
    _uint,
)


class WeightError(ValueError):
    """The snapshot or report is unsuitable for calculating weights."""


@dataclass(frozen=True)
class MinerSlot:
    uid: int
    hotkey: str
    registered_at: int


@dataclass(frozen=True)
class ChainSnapshot:
    genesis_hash: str
    netuid: int
    block: int
    block_hash: str
    miners: tuple[MinerSlot, ...]


def load_snapshot(raw: bytes) -> ChainSnapshot:
    """Parse a trusted snapshot of the eligible miner roster at one block."""
    try:
        data = _read_json(raw)
        fields = {"genesis_hash", "netuid", "block", "block_hash", "miners"}
        if isinstance(data, dict) and "validator_hotkeys" in data:
            fields.add("validator_hotkeys")
        snapshot = _fields(data, fields, label="snapshot")
        genesis_hash = _chain_hash(snapshot["genesis_hash"], label="genesis_hash")
        netuid = _uint(snapshot["netuid"], 16, label="netuid")
        block = _uint(snapshot["block"], 32, label="block")
        block_hash = _chain_hash(snapshot["block_hash"], label="block_hash")
        rows = snapshot["miners"]
        if not isinstance(rows, list) or len(rows) > 65_536:
            raise WeightError("snapshot miners must be an array of at most 65536 rows")

        miners = []
        seen_uids = set()
        seen_hotkeys = set()
        for value in rows:
            row = _fields(value, {"uid", "hotkey", "registered_at"}, label="miner slot")
            uid = _uint(row["uid"], 16, label="uid")
            hotkey = _hotkey(row["hotkey"])
            registered_at = _uint(row["registered_at"], 32, label="registered_at")
            if registered_at > block:
                raise WeightError("miner registration is newer than the snapshot")
            if uid in seen_uids or hotkey in seen_hotkeys:
                raise WeightError("snapshot contains a duplicate miner UID or hotkey")
            seen_uids.add(uid)
            seen_hotkeys.add(hotkey)
            miners.append(MinerSlot(uid, hotkey, registered_at))

        # Roster exports include permit information for inspection. Window
        # scoring uses the same miner slots with or without that metadata.
        validators = snapshot.get("validator_hotkeys", [])
        if not isinstance(validators, list) or len(validators) > len(miners):
            raise WeightError("snapshot validator_hotkeys must be a list of registered hotkeys")
        validator_hotkeys = {_hotkey(value) for value in validators}
        if len(validator_hotkeys) != len(validators) or not validator_hotkeys <= seen_hotkeys:
            raise WeightError("snapshot validator_hotkeys must be unique and registered")
    except ReportError as error:
        raise WeightError(f"invalid snapshot: {error}") from error

    return ChainSnapshot(genesis_hash, netuid, block, block_hash, tuple(miners))


def preview_weights(
    report: WorkReport, snapshot: ChainSnapshot, window_blocks: int
) -> dict[int, int]:
    """Return positive raw weights in UID order using the report's end-block roster."""
    if type(window_blocks) is not int or window_blocks <= 0:
        raise WeightError("window length in blocks must be a positive integer")
    if (report.genesis_hash, report.netuid) != (snapshot.genesis_hash, snapshot.netuid):
        raise WeightError("report and snapshot belong to different networks or subnets")
    if (report.end_block, report.end_block_hash) != (snapshot.block, snapshot.block_hash):
        raise WeightError("report end block and hash must match the trusted snapshot")
    if report.end_block - report.start_block != window_blocks:
        raise WeightError("report duration does not match the configured scoring window")

    work_by_hotkey = {work.hotkey: work for work in report.miners}
    weights = {}
    for slot in sorted(snapshot.miners, key=lambda slot: slot.uid):
        work = work_by_hotkey.get(slot.hotkey)
        if work is None or work.registered_at != slot.registered_at:
            continue
        if slot.registered_at < report.end_block and work.accepted_work > 0:
            weights[slot.uid] = work.accepted_work
    return weights
