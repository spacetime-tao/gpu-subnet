"""Check UID ownership before broadcast and recover historical transactions."""

from collections.abc import Awaitable, Callable, Iterator
from contextlib import contextmanager
from contextvars import ContextVar
from hashlib import blake2b
from typing import Any

from .roster import ChainError

BroadcastCheck = Callable[[Any, str], Awaitable[None]]


def make_guarded_client(
    sdk, network: str, *, allow_failover: bool = True, pin_finality: bool = False,
):
    """Keep the pinned SDK's connection defaults and signed submission flow."""

    class GuardedRpcSubstrate(sdk.RpcSubstrate):
        _before_weight_broadcast: ContextVar[BroadcastCheck | None] = (
            ContextVar("before_weight_broadcast", default=None)
        )

        async def find_extrinsic(self, extrinsic_hash, block_hash, *, on_match=None):
            """Report a raw transaction match before decoding its outcome."""
            from bittensor._transport.contract import InclusionReport
            from bittensor._transport.errors import StateDiscardedError
            from bittensor._transport.extrinsics import resolve_outcome

            # Inspect the raw block before reading runtime metadata or events.
            async def locate(raw):
                response = await raw._session.request("chain_getBlock", [block_hash])
                if response is None:
                    # An unavailable body cannot establish transaction absence.
                    raise StateDiscardedError(block_hash)
                try:
                    block = response["block"]
                    block_number = int(block["header"]["number"], 16)
                    extrinsics = block["extrinsics"]
                    if not isinstance(extrinsics, list) or block_number < 0:
                        raise ValueError("invalid block fields")
                    for index, extrinsic in enumerate(extrinsics):
                        if not isinstance(extrinsic, str) or not extrinsic.startswith("0x"):
                            raise ValueError("invalid extrinsic bytes")
                        encoded = bytes.fromhex(extrinsic[2:])
                        if not encoded:
                            raise ValueError("empty extrinsic bytes")
                        if "0x" + blake2b(encoded, digest_size=32).hexdigest() == extrinsic_hash:
                            return block_number, index
                except (KeyError, TypeError, ValueError) as error:
                    raise ChainError("chain returned malformed block data during transaction lookup") from error
                return None

            match = None

            # Keep an exact match across the SDK's archive retry. When the
            # archive supplied the block body, it also supplies the events.
            async def lookup(raw):
                nonlocal match
                if match is None:
                    match = await locate(raw)
                    if match is None:
                        return None
                    if on_match is not None:
                        on_match(*match)
                block_number, index = match
                codec = await raw._runtimes.codec_at(block_hash)
                events = await raw.get_events(block_hash=block_hash)
                triggered = [event for event in events if event.get("extrinsic_idx") == index]
                outcome = resolve_outcome(triggered, codec)
                return InclusionReport(
                    extrinsic_hash=extrinsic_hash, block_hash=block_hash,
                    block_number=block_number, extrinsic_idx=index,
                    is_success=outcome["is_success"],
                    total_fee_amount=outcome["total_fee_amount"], weight=outcome["weight"],
                    triggered_events=triggered, error_message=outcome["error_message"],
                )

            report = await self._read(lookup)
            return None if report is None else self._result_from_report(report, True)

        _height_read_socket = None

        async def _read_height(self, operation):
            from bittensor._substrate import _public_request_error
            from bittensor._transport.errors import SubstrateRequestException

            # If the SDK reconnects, even to the same URL, a different node
            # can answer. Fail the scan before accepting any mixed heights.
            raw = self.raw
            session = raw._session
            socket = session._ws
            if socket is None or (
                self._height_read_socket is not None and self._height_read_socket is not socket
            ):
                raise ChainError("primary RPC connection changed during block lookup; retry the command")
            self._height_read_socket = socket
            try:
                value = await operation(raw)
            except SubstrateRequestException as error:
                raise _public_request_error(error) from error
            if session._ws is not socket:
                raise ChainError("primary RPC connection changed during block lookup; retry the command")
            return value

        async def block_hash(self, block=None):
            if pin_finality:
                return await self._read_height(lambda raw: raw.get_block_hash(block))
            return await super().block_hash(block)

        async def finalized_block_number(self):
            if pin_finality:
                return await self._read_height(lambda raw: raw.get_finalized_block_number())
            return await super().finalized_block_number()

        async def _submit_and_report(
            self,
            extrinsic,
            *,
            signer_address,
            wait_for_inclusion,
            wait_for_finalization,
            reservation=None,
            reset_nonce_cache=True,
        ):
            # SDK 11.3.2 calls this with the signed extrinsic. Its next write
            # is raw.submit_extrinsic, which broadcasts without signing again.
            try:
                check = self._before_weight_broadcast.get()
                if check is None:
                    raise ChainError("broadcast requires an active guard")
                await check(extrinsic, signer_address)
            except BaseException:
                # A veto or cancellation here definitely precedes broadcast.
                abandoned = reservation
                if abandoned is None and reset_nonce_cache and extrinsic.nonce is not None:
                    abandoned = (extrinsic.nonce, 1)
                if abandoned is not None:
                    self.release_nonce_reservation(signer_address, *abandoned)
                raise

            return await super()._submit_and_report(
                extrinsic,
                signer_address=signer_address,
                wait_for_inclusion=wait_for_inclusion,
                wait_for_finalization=wait_for_finalization,
                reservation=reservation,
                reset_nonce_cache=reset_nonce_cache,
            )

    label, endpoint = sdk.settings.resolve_endpoint(network)
    fallbacks = sdk.settings.default_fallback_endpoints(label) if allow_failover else []
    substrate = GuardedRpcSubstrate(
        endpoint,
        fallback_endpoints=[url for url in fallbacks if url != endpoint],
        archive_endpoints=sdk.settings.default_archive_endpoints(label),
    )
    return sdk.Client(network, substrate=substrate)


@contextmanager
def guard_broadcast(client, check: BroadcastCheck) -> Iterator[None]:
    """Install the check for one submission scope on this client."""
    substrate = getattr(client, "_substrate", None)
    hook = getattr(substrate, "_before_weight_broadcast", None)
    if hook is None:
        raise ChainError("weight submission requires a client with a broadcast guard")

    active = True

    async def scoped_check(extrinsic, signer_address):
        if not active:
            raise ChainError("broadcast requires an active guard")
        await check(extrinsic, signer_address)
        if not active:
            raise ChainError("broadcast requires an active guard")

    # A child task keeps its copied ContextVar after this scope exits.
    token = hook.set(scoped_check)
    try:
        yield
    finally:
        active = False
        hook.reset(token)
