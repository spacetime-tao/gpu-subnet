"""Build and send Bittensor weight intents using the pinned SDK."""

import asyncio

from .roster import ChainError
from .uid_guard import guard_broadcast
from .weight_encoding import U16_MAX, encode_weights

_U64_MAX = (1 << 64) - 1
_WEIGHT_ERA_BLOCKS = 8
_FINALIZATION_WATCH_SECONDS = 180
_WATCH_CLEANUP_SECONDS = 2


async def prepare_submission(
    sdk, client, wallet, *, netuid: int, weights: dict[int, int], version_key: int
):
    """Check the requested weight vector and quote its unsigned transaction."""
    if type(netuid) is not int or not 1 <= netuid <= U16_MAX:
        raise ChainError("weight submission requires a non-root subnet UID")
    if type(version_key) is not int or not 0 <= version_key <= _U64_MAX:
        raise ChainError("weights version key must be an unsigned 64-bit integer")

    cap = await client.hyperparameters.max_weight_limit(netuid=netuid)
    encoded = encode_weights(weights, cap)
    await _check_version(client, netuid, version_key)

    intent = _encoded_intent(sdk, netuid, encoded, version_key)
    plan = await client.plan(
        intent, wallet, period=_WEIGHT_ERA_BLOCKS, shielded=False
    )
    if not plan.ok:
        violations = ", ".join(plan.violations)
        raise ChainError(f"weight plan rejected ({violations})")

    receipt = plan.to_dict()
    receipt["encoded_weights"] = encoded
    receipt["max_weight_limit_u16"] = cap
    receipt["transaction_period_blocks"] = _WEIGHT_ERA_BLOCKS
    receipt["submission_path"] = "direct_weights"
    if (reveal_round := plan.extras.get("reveal_round")) is not None:
        receipt["submission_path"] = "timelocked_commit"
        receipt["reveal_round"] = reveal_round
    return intent, receipt


async def submit_weights(client, wallet, intent, *, before_broadcast) -> dict:
    """Submit once and distinguish unknown admission, direct set, and queued reveal."""
    await _check_version(client, intent.netuid, intent.version_key)
    deadline = asyncio.timeout(None)

    async def begin_watch(extrinsic, signer_address):
        await before_broadcast(extrinsic, signer_address)
        deadline.reschedule(asyncio.get_running_loop().time() + _FINALIZATION_WATCH_SECONDS)

    with guard_broadcast(client, begin_watch):
        try:
            async with deadline:
                execution = asyncio.create_task(client.execute(
                    intent, wallet, wait_for_inclusion=True, wait_for_finalization=True,
                    period=_WEIGHT_ERA_BLOCKS, shielded=False, retries=0,
                ))
                result = await asyncio.shield(execution)
        except TimeoutError:
            if not deadline.expired():
                raise
            await _stop_watch(execution)
            return {
                "status": "submission_unconfirmed",
                "success": False,
                "message": "finalization watch timed out; reconcile the recorded transaction",
            }
        except asyncio.CancelledError:
            await _stop_watch(execution)
            raise

    receipt = result.to_dict()
    if result.data.get("submission_outcome_unknown") or (result.success and not result.block_hash):
        receipt["status"] = "submission_unconfirmed"
    elif not result.success:
        receipt["status"] = "submission_failed"
    elif (reveal_round := result.data.get("reveal_round")) is not None:
        receipt["status"] = "commit_queued"
        receipt["reveal_round"] = reveal_round
    else:
        receipt["status"] = "weights_submitted"
    return receipt


async def _stop_watch(execution: asyncio.Task) -> None:
    # The pinned SDK awaits an unsubscribe RPC in the cancellation path.
    # Drop a stalled unsubscribe too, and join the task before releasing the slot.
    execution.cancel()
    try:
        await asyncio.wait({execution}, timeout=_WATCH_CLEANUP_SECONDS)
    finally:
        if not execution.done():
            execution.cancel()
        await asyncio.gather(execution, return_exceptions=True)


def _encoded_intent(sdk, netuid: int, encoded: dict[int, int], version_key: int):
    # These build helpers are pinned with SDK 11.3.2. The SDK's built-in
    # raw_u16 intent is Null-only. Use its exact-vector validation for both
    # modes while retaining its registration, timing, and timelock logic.
    from bittensor.intents.weights import (
        DEFAULT_COMMIT_REVEAL_VERSION,
        _build_timelocked,
        _conform,
        _preflight,
    )

    class EncodedSetWeights(sdk.SetWeights):
        async def build(self, substrate, wallet):
            preflight = await _preflight(
                substrate, self.hotkey_address(wallet), self.netuid, self.mechid
            )
            uids, values = _conform(
                self.uids, self.weights, preflight, self.netuid, raw_u16=True
            )
            if preflight.commit_reveal:
                return await _build_timelocked(
                    substrate, self.hotkey_public_key(wallet), self.netuid, self.mechid,
                    uids, values, self.version_key, DEFAULT_COMMIT_REVEAL_VERSION,
                )
            return await substrate.compose(sdk.calls.SubtensorModule.set_mechanism_weights(
                netuid=self.netuid, mecid=self.mechid, dests=uids, weights=values,
                version_key=self.version_key,
            ))

    return EncodedSetWeights(netuid=netuid, weights=encoded, version_key=version_key)


async def _check_version(client, netuid: int, version_key: int) -> None:
    required_version = await client.query(("SubtensorModule", "WeightsVersionKey"), [netuid])
    if type(required_version) is not int or not 0 <= required_version <= _U64_MAX:
        raise ChainError("chain returned an invalid weights version key")
    if version_key < required_version:
        raise ChainError(
            f"weights version key {version_key} is below the subnet's {required_version}"
        )
