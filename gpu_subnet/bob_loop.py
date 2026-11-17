"""Poll verified Bob Labs reports on a subnet's chain cadence."""

import asyncio
from collections.abc import Awaitable, Callable
from math import isfinite

from .bob_scores import BobReport
from .evidence import ReportError, _chain_hash, _uint
from .roster import ChainError


_HANDLED = {
    "preview_ready", "no_eligible_work", "duplicate_window", "weights_submitted", "commit_queued",
}
_SKIPPED = {"stale_report", "future_report", "window_skipped"}


async def _timing(client, netuid: int, validator_hotkey: str | None) -> tuple[int, int, int]:
    """Read one finalized height, its cadence, and the validator's last update."""
    substrate = client._substrate
    try:
        block = _uint(await client.finalized_block(), 64, label="finalized block")
        block_hash = _chain_hash(await substrate.block_hash(block), label="finalized block hash")
        tempo, rate = await asyncio.gather(
            substrate.query("SubtensorModule", "Tempo", [netuid], block_hash=block_hash),
            substrate.query("SubtensorModule", "WeightsSetRateLimit", [netuid], block_hash=block_hash),
        )
        tempo = _uint(tempo, 16, label="subnet tempo")
        rate = _uint(rate, 64, label="weights rate limit")
        if tempo == 0:
            raise ChainError("the subnet has no positive tempo")

        last_update = 0
        if validator_hotkey is not None:
            uid, updates = await asyncio.gather(
                substrate.query(
                    "SubtensorModule", "Uids", [netuid, validator_hotkey], block_hash=block_hash,
                ),
                substrate.query("SubtensorModule", "LastUpdate", [netuid], block_hash=block_hash),
            )
            if uid is None:
                raise ChainError("the validator hotkey is unregistered at the finalized head")
            uid = _uint(uid, 16, label="validator UID")
            if not isinstance(updates, (list, tuple)) or uid >= len(updates):
                raise ChainError("the finalized head has no last-update entry for the validator")
            last_update = _uint(updates[uid], 64, label="last weight update")
            if last_update > block:
                raise ChainError("the last weight update is ahead of the finalized head")
    except ReportError as error:
        raise ChainError(str(error)) from error

    return block, max(tempo, rate), last_update


async def run_bob_loop(
    client,
    *,
    netuid: int,
    fetch_report: Callable[[], Awaitable[BobReport]],
    run_report: Callable[[BobReport], Awaitable[dict]],
    emit: Callable[[dict], None],
    validator_hotkey: str | None = None,
    max_polls: int | None = None,
    sleep: Callable[[float], Awaitable[None]] = asyncio.sleep,
) -> dict:
    """Poll no more often than one tempo and the weights rate limit.

    The caller supplies the preview or explicitly enabled submission callback.
    A failed or unknown attempt stops the loop. Retries across processes remain
    subject to the submission journal.
    """
    if type(netuid) is not int or not 1 <= netuid <= 65_535:
        raise ChainError("polling requires a non-root subnet number")
    if max_polls is not None and (type(max_polls) is not int or max_polls < 1):
        raise ChainError("maximum polls must be positive")

    previous_block = None
    last_poll_block = None
    last_handled = None
    last_window_submitted = False
    polls = 0
    while True:
        block, interval, last_update = await _timing(client, netuid, validator_hotkey)
        if previous_block is not None and block < previous_block:
            raise ChainError("the finalized head moved backward")
        previous_block = block
        if last_update or last_poll_block is not None:
            anchor = max(last_update, last_poll_block or 0)
            remaining = anchor + interval - block
            if remaining > 0:
                seconds_per_block = await client.block_time()
                if not isfinite(seconds_per_block) or seconds_per_block <= 0:
                    raise ChainError("the chain reported an invalid block time")
                await sleep(min(60.0, max(1.0, remaining * seconds_per_block)))
                continue

        last_poll_block = block
        report = await fetch_report()
        older = last_handled is not None and report.end_ts < last_handled.end_ts
        repeated = (
            last_handled is not None and report.end_ts == last_handled.end_ts
            and (last_window_submitted or report.digest == last_handled.digest)
        )
        if older or repeated:
            receipt = {
                "status": "duplicate_window",
                "reason": "older_window" if older else "window_already_processed",
                "netuid": netuid,
                "end_ts": report.end_ts,
                "report_digest": report.digest,
            }
        else:
            receipt = await run_report(report)
            if receipt["status"] in _HANDLED:
                last_handled = report
                last_window_submitted = receipt["status"] in ("weights_submitted", "commit_queued")
        emit(receipt)
        polls += 1
        if (
            receipt["status"] not in _HANDLED and receipt["status"] not in _SKIPPED
        ) or polls == max_polls:
            return receipt
