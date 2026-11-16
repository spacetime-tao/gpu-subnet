"""Reconcile a signed weight transaction with finalized Bittensor state."""

from collections.abc import Callable
from hashlib import blake2b

from .evidence import _chain_hash, _uint
from .roster import ChainError, read_roster

# Subtensor's mechanism storage stride and event layouts, as used by SDK 11.3.2.
_MECHANISM_STRIDE = 4096
_INCLUSION_VERIFIED = "inclusion_verified"
_SUCCESSFUL_READBACKS = {
    "commit_pending", "reveal_applied", "reveal_unconfirmed", "roster_mismatch",
    "weights_applied", "weights_mismatch",
}
_SUCCESSFUL_RECEIPTS = {"weights_submitted", "commit_queued", "submission_needs_review"}


class _InclusionDisagreement(Exception):
    def __init__(self, block: int, block_hash: str):
        self.block = block
        self.block_hash = block_hash


async def reconcile_submission(
    client, entry: dict, *, save_inclusion: Callable[[dict], None] | None = None,
) -> dict:
    """Read finalized inclusion, weight rows and timelock state without sending."""
    attempt = entry["attempt"]
    tx_hash = _chain_hash(attempt["extrinsic_hash"], label="signed extrinsic hash")
    finalized = _uint(await client.finalized_block(), 32, label="finalized block")
    substrate = client._substrate
    if await substrate.block_hash(0) != attempt["genesis_hash"]:
        raise ChainError("submission record is for a different chain")

    first = _uint(attempt["scan_start_block"], 32, label="submission scan start")
    broadcast_block = _uint(attempt["broadcast_head_block"], 32, label="broadcast block")
    period = _uint(attempt["transaction_period_blocks"], 16, label="transaction period")
    if period < 4 or period & (period - 1) or first > broadcast_block + 1:
        raise ChainError("submission record has an invalid mortal scan range")
    # The SDK anchors the era no later than the best block sampled before
    # broadcast. This upper bound can be later than its actual expiration.
    last = broadcast_block + period
    receipt = entry.get("receipt") or {}
    submission = receipt.get("submission", receipt)
    if not isinstance(submission, dict):
        submission = receipt
    previous = entry.get("readback") or {}
    previous_inclusion = _remembered_inclusion(previous, first, last)
    previous_dispatch = _dispatch_outcome(previous) if previous_inclusion else None
    receipt_hint = _receipt_block(submission)
    receipt_hash = None
    if (
        submission.get("status", receipt.get("status")) in _SUCCESSFUL_RECEIPTS
        and submission.get("success") is True and submission.get("block_hash")
    ):
        receipt_hash = _chain_hash(submission["block_hash"], label="saved receipt block hash")

    result = {"extrinsic_hash": tx_hash, "finalized_block": finalized}
    if receipt_hash is not None:
        receipt_inclusion = None
        if receipt_hint is not None:
            if not first <= receipt_hint <= last:
                raise ChainError("saved successful receipt is outside the recorded scan range")
            receipt_inclusion = receipt_hint, receipt_hash
        if previous_inclusion is not None and (
            previous_inclusion[1] != receipt_hash
            or (receipt_inclusion is not None and previous_inclusion != receipt_inclusion)
            or previous_dispatch is False
        ):
            return _inclusion_conflict(
                {
                    **result, "receipt_block_hash": receipt_hash,
                    "observed_inclusion_block": previous_inclusion[0],
                    "observed_inclusion_block_hash": previous_inclusion[1],
                    "observed_dispatch_success": previous_dispatch,
                },
                receipt_inclusion, True, "prior readback conflicts with the saved successful receipt",
            )
        previous_inclusion = receipt_inclusion or previous_inclusion
        previous_dispatch = True

    if previous_inclusion is not None and finalized < previous_inclusion[0]:
        return {
            **result, "status": "awaiting_finality",
            "reason": "the node is behind the previously observed finalized inclusion",
        }

    def record_match(block, block_hash, index):
        if (
            (previous_inclusion is not None and (block, block_hash) != previous_inclusion)
            or (receipt_hash is not None and block_hash != receipt_hash)
        ):
            # Exact location is already known. No event data is needed to report this conflict.
            raise _InclusionDisagreement(block, block_hash)
        if save_inclusion is not None:
            save_inclusion({
                **result, "status": _INCLUSION_VERIFIED, "inclusion_block": block,
                "inclusion_block_hash": block_hash, "extrinsic_id": f"{block}-{index:04d}",
            })

    hint = previous_inclusion[0] if previous_inclusion else receipt_hint
    try:
        inclusion = await _find_inclusion(
            substrate, tx_hash, first, min(last, finalized), hint, record_match,
        )
    except _InclusionDisagreement as error:
        return _inclusion_conflict(
            {
                **result, "observed_inclusion_block": error.block,
                "observed_inclusion_block_hash": error.block_hash,
            },
            previous_inclusion, previous_dispatch,
            "the finalized transaction location conflicts with saved inclusion evidence",
        )

    if inclusion is None:
        if previous_inclusion is not None:
            return _inclusion_conflict(
                result, previous_inclusion, previous_dispatch,
                "the finalized scan missed the previously included transaction",
            )
        scan_complete = finalized >= last
        if scan_complete and receipt_hash is not None:
            return _inclusion_conflict(
                {**result, "receipt_block_hash": receipt_hash}, None, previous_dispatch,
                "the finalized scan missed the transaction from the saved successful receipt",
            )
        status = "expired_unseen" if scan_complete else "awaiting_finality"
        return {
            **result,
            "status": status,
            "scan_start_block": first,
            "scan_end_block": min(last, finalized),
            "expiry_upper_bound": last,
        }

    block, block_hash, extrinsic = inclusion
    result["inclusion_block"] = block
    result["inclusion_block_hash"] = block_hash
    result["extrinsic_id"] = extrinsic.extrinsic_id
    failed = _event_fields(extrinsic.events, "System", "ExtrinsicFailed")
    succeeded = _event_fields(extrinsic.events, "System", "ExtrinsicSuccess")
    if failed and (succeeded or extrinsic.success is True):
        return _inclusion_conflict(
            result, (block, block_hash), previous_dispatch,
            "the finalized extrinsic has conflicting dispatch evidence",
        )

    dispatch = None
    if extrinsic.success is True:
        dispatch = True
    elif extrinsic.success is False and failed:
        dispatch = False
    if previous_dispatch is not None and dispatch is not None and dispatch != previous_dispatch:
        return _inclusion_conflict(
            {**result, "observed_dispatch_success": dispatch},
            (block, block_hash), previous_dispatch,
            "the finalized dispatch outcome conflicts with saved inclusion evidence",
        )

    remembered_dispatch = previous_dispatch if dispatch is None else dispatch
    if remembered_dispatch is not None:
        result["dispatch_success"] = remembered_dispatch
    if dispatch is not True:
        return {
            **result,
            "status": "dispatch_failed" if dispatch is False else "inclusion_unconfirmed",
            "reason": extrinsic.message,
        }

    # Record dispatch separately before reading the historical state needed for the audit.
    if save_inclusion is not None:
        save_inclusion({**result, "status": _INCLUSION_VERIFIED})

    index = attempt["mechid"] * _MECHANISM_STRIDE + attempt["netuid"]
    hotkey = attempt["validator_hotkey"]
    writes = _weight_writes(extrinsic.events, index)
    commits = [
        fields
        for fields in _subtensor_event_fields(extrinsic.events, "TimelockedWeightsCommitted", 4)
        if fields[:2] == (hotkey, index)
    ]
    if len(writes) == 1 and not commits:
        return {**result, **await _check_weights(client, attempt, block_hash, index, writes[0])}
    if len(commits) == 1 and not writes:
        _, _, commit_hash, round_number = commits[0]
        if isinstance(commit_hash, (bytes, bytearray, list, tuple)):
            commit_hash = "0x" + _encoded_bytes(commit_hash).hex()
        return await _check_commit(
            client, attempt, result, index,
            _chain_hash(commit_hash, label="weight commitment hash"),
            _uint(round_number, 64, label="reveal round"),
        )
    return {
        **result, "status": "inclusion_unconfirmed",
        "reason": "finalized extrinsic has no unique matching weight or commitment event",
    }


def _remembered_inclusion(readback, first, last):
    if "inclusion_block" not in readback and "inclusion_block_hash" not in readback:
        return None
    block = _uint(readback.get("inclusion_block"), 32, label="previous inclusion block")
    block_hash = _chain_hash(readback.get("inclusion_block_hash"), label="previous inclusion hash")
    if not first <= block <= last:
        raise ChainError("previously included transaction is outside the recorded scan range")
    return block, block_hash


def _dispatch_outcome(readback: dict) -> bool | None:
    """Read dispatch evidence, including statuses saved by older validators."""
    outcome = readback.get("dispatch_success")
    if type(outcome) is bool:
        return outcome
    status = readback.get("status")
    if status in _SUCCESSFUL_READBACKS:
        return True
    if status == "dispatch_failed":
        return False
    return None


def _inclusion_conflict(result, previous_inclusion, previous_dispatch, reason):
    if previous_inclusion is not None:
        block, block_hash = previous_inclusion
        result = {**result, "inclusion_block": block, "inclusion_block_hash": block_hash}
    return {
        **result,
        "status": "inclusion_unconfirmed",
        "reason": reason,
        "inclusion_conflict": True,
        "dispatch_success": previous_dispatch,
    }


def _receipt_block(receipt):
    extrinsic_id = receipt.get("extrinsic_id")
    if isinstance(extrinsic_id, str):
        height, _, _ = extrinsic_id.partition("-")
        if height.isascii() and height.isdecimal() and len(height) <= 10:
            return int(height)
    return None


async def _find_inclusion(substrate, tx_hash, first, last, hint, on_match):
    # Always verify the transaction hash on the current finalized chain.
    if hint is not None and first <= hint <= last:
        found = await _find_at(substrate, tx_hash, hint, on_match)
        if found is not None:
            return found
    for block in range(first, last + 1):
        if block != hint:
            found = await _find_at(substrate, tx_hash, block, on_match)
            if found is not None:
                return found
    return None


async def _find_at(substrate, tx_hash, block, on_match):
    block_hash = _chain_hash(await substrate.block_hash(block), label="finalized block hash")

    def record_match(block_number, extrinsic_index):
        if _uint(block_number, 32, label="transaction block number") != block:
            raise ChainError("extrinsic lookup returned a different block number")
        on_match(block, block_hash, _uint(extrinsic_index, 32, label="transaction index"))

    result = await substrate.find_extrinsic(tx_hash, block_hash, on_match=record_match)
    if result is None:
        return None
    if result.block_hash != block_hash:
        raise ChainError("extrinsic lookup returned a different block hash")
    return block, block_hash, result


def _event_fields(events, module, event_id):
    fields = []
    for record in events:
        event = record.get("event", record) if isinstance(record, dict) else None
        if isinstance(event, dict) and (event.get("module_id"), event.get("event_id")) == (
            module, event_id
        ):
            fields.append(event.get("attributes"))
    return fields


def _subtensor_event_fields(events, event_id, count):
    return [
        tuple(fields) for fields in _event_fields(events, "SubtensorModule", event_id)
        if isinstance(fields, (list, tuple)) and len(fields) == count
    ]


def _weight_writes(events, index):
    return [
        uid for mechanism, uid in _subtensor_event_fields(events, "WeightsSet", 2)
        if mechanism == index and type(uid) is int
    ]


def _encoded_bytes(value):
    try:
        if isinstance(value, str):
            return bytes.fromhex(value.removeprefix("0x"))
        if isinstance(value, (bytes, bytearray, list, tuple)):
            return bytes(value)
    except (TypeError, ValueError) as error:
        raise ChainError("chain returned invalid encoded commitment bytes") from error
    raise ChainError("chain returned invalid encoded commitment bytes")


async def _check_weights(client, attempt, block_hash, index, validator_uid):
    roster = await read_roster(client, attempt["netuid"], block_hash=block_hash)
    if roster.snapshot.genesis_hash != attempt["genesis_hash"]:
        raise ChainError("weight readback roster is on a different chain")
    slots = {slot.uid: slot for slot in roster.snapshot.miners}
    validator = slots.get(validator_uid)
    changed = []
    for target in attempt["targets"]:
        slot = slots.get(target["uid"])
        if slot is None or (slot.hotkey, slot.registered_at) != (
            target["hotkey"], target["registered_at"]
        ):
            changed.append(target["uid"])

    pairs = await client._substrate.query(
        "SubtensorModule", "Weights", [index, validator_uid], block_hash=block_hash
    )
    if not isinstance(pairs, (list, tuple)):
        raise ChainError("chain returned an invalid stored weight row")
    observed = {}
    for pair in pairs:
        if not isinstance(pair, (list, tuple)) or len(pair) != 2:
            raise ChainError("chain returned an invalid stored weight pair")
        uid = _uint(pair[0], 16, label="stored weight UID")
        if uid in observed:
            raise ChainError("chain returned a duplicate stored weight UID")
        observed[uid] = _uint(pair[1], 16, label="stored weight")
    expected = {int(uid): value for uid, value in attempt["encoded_weights"].items()}
    status = "weights_applied"
    if changed or validator is None or validator.hotkey != attempt["validator_hotkey"]:
        status = "roster_mismatch"
    elif observed != expected:
        status = "weights_mismatch"
    return {
        "status": status,
        "weights_block_hash": block_hash,
        "validator_uid": validator_uid,
        "observed_weights": observed,
        "changed_uids": changed,
    }


async def _check_commit(client, attempt, result, index, commit_hash, reveal_round):
    substrate = client._substrate
    hotkey = attempt["validator_hotkey"]
    block = result["inclusion_block"]
    target = (block, reveal_round, commit_hash)
    result.update(commit_hash=commit_hash, reveal_round=reveal_round)

    def unconfirmed(reason):
        return {**result, "status": "reveal_unconfirmed", "reason": reason}

    async def queue_at(block_hash):
        rows = await substrate.query_map(
            "SubtensorModule", "TimelockedWeightCommits", [index], block_hash=block_hash
        )
        if not isinstance(rows, (list, tuple)):
            raise ChainError("chain returned an invalid commitment queue")
        epochs = set()
        pending = {}
        for row in rows:
            if not isinstance(row, (list, tuple)) or len(row) != 2:
                raise ChainError("chain returned an invalid commitment queue")
            epoch, commits = row
            epoch = _uint(epoch, 64, label="commitment queue epoch")
            if epoch in epochs:
                return None
            epochs.add(epoch)
            if commits is None:
                continue
            if not isinstance(commits, (list, tuple)):
                raise ChainError("chain returned an invalid commitment queue")
            for item in commits:
                if not isinstance(item, (list, tuple)) or len(item) != 4:
                    raise ChainError("chain returned an invalid queued commitment")
                signer, commit_block, ciphertext, round_number = item
                if signer != hotkey:
                    continue
                identity = (
                    _uint(commit_block, 64, label="commit block"),
                    _uint(round_number, 64, label="queued reveal round"),
                    "0x" + blake2b(_encoded_bytes(ciphertext), digest_size=32).hexdigest(),
                )
                if identity in pending:
                    return None
                pending[identity] = epoch
        return pending

    finalized = result["finalized_block"]
    before = await queue_at(result["inclusion_block_hash"])
    if before is None or target not in before:
        return unconfirmed("the exact commitment is not uniquely visible in the inclusion queue")
    commit_epoch = before[target]
    if finalized == block:
        return {**result, "status": "commit_pending"}
    disappearance_hash = await substrate.block_hash(finalized)
    after = await queue_at(disappearance_hash)
    if after is None or after.get(target, commit_epoch) != commit_epoch:
        return unconfirmed("the commitment queue has inconsistent or duplicate entries")
    if target in after:
        return {**result, "status": "commit_pending"}

    # On the finalized chain this entry cannot reappear after removal: its
    # identity includes the actual commit block and ciphertext hash.
    low, high = block, finalized
    while low + 1 < high:
        middle = (low + high) // 2
        middle_hash = await substrate.block_hash(middle)
        pending = await queue_at(middle_hash)
        if pending is None or pending.get(target, commit_epoch) != commit_epoch:
            return unconfirmed("the commitment queue has inconsistent or duplicate entries")
        if target in pending:
            low, before = middle, pending
        else:
            high, disappearance_hash, after = middle, middle_hash, pending

    result["queue_disappearance_block"] = high
    result["queue_disappearance_block_hash"] = disappearance_hash
    events = await substrate.events(disappearance_hash)
    reveals = _subtensor_event_fields(events, "TimelockedWeightsRevealed", 2)
    if (
        before.items() - after.items() != {(target, commit_epoch)}
        or reveals.count((index, hotkey)) != 1
        or not _commit_additions_match(events, index, hotkey, high, after.keys() - before.keys())
    ):
        return unconfirmed("queue removal cannot be uniquely attributed to a reveal")

    validator_uid = await substrate.query(
        "SubtensorModule", "Uids", [attempt["netuid"], hotkey], block_hash=disappearance_hash
    )
    if type(validator_uid) is not int or _weight_writes(events, index).count(validator_uid) != 1:
        return unconfirmed("reveal block does not contain a unique validator weight write")
    observed = await _check_weights(client, attempt, disappearance_hash, index, validator_uid)
    if observed["status"] == "weights_applied":
        observed["status"] = "reveal_applied"
    return {**result, **observed}


def _commit_additions_match(events, index, hotkey, block, added):
    # A same-block commit that is absent from both snapshots could also be
    # responsible for the reveal event, which does not identify its ciphertext.
    committed = set()
    for fields in _event_fields(events, "SubtensorModule", "TimelockedWeightsCommitted"):
        if not isinstance(fields, (list, tuple)) or len(fields) != 4:
            return False
        signer, mechanism, digest, round_number = fields
        if (signer, mechanism) == (hotkey, index):
            identity = (
                block,
                _uint(round_number, 64, label="commit event reveal round"),
                "0x" + _encoded_bytes(digest).hex(),
            )
            if identity in committed:
                return False
            committed.add(identity)
    return committed == added
