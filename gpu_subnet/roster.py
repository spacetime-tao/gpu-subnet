"""Read the registered subnet roster at one Bittensor block hash."""

from dataclasses import dataclass

from .evidence import ReportError, _chain_hash, _hotkey, _uint
from .weights import ChainSnapshot, MinerSlot


class ChainError(ValueError):
    """Chain data could not be used by the validator."""


@dataclass(frozen=True)
class Roster:
    snapshot: ChainSnapshot
    validator_hotkeys: frozenset[str]


async def read_roster(
    client, netuid: int, *, block: int | None = None, finalized: bool = True,
    block_hash: str | None = None,
) -> Roster:
    """Read registered slots by height or at an exact hash from an inclusion receipt."""
    try:
        _uint(netuid, 16, label="subnet ID")
        if netuid == 0:
            raise ChainError("root subnet does not have a miner roster")
        if block is not None:
            _uint(block, 32, label="requested block")
        # SDK 11.3.2's public client pins by height. Use its transport to read
        # the graph at the exact hash we record, even if the best head forks.
        substrate = client._substrate
        if block_hash is None:
            head = await (client.finalized_block() if finalized else client.block())
            _uint(head, 32, label="chain block")
            if block is None:
                block = head
            if block > head:
                head_name = "finalized head" if finalized else "chain head"
                raise ChainError(f"requested block {block} is newer than the {head_name} ({head})")
            block_hash = await substrate.block_hash(block)

        genesis_hash = _chain_hash(await substrate.block_hash(0), label="genesis hash")
        block_hash = _chain_hash(block_hash, label="block hash")
        graph = await substrate.runtime_call(
            "SubnetInfoRuntimeApi", "get_metagraph", [netuid], block_hash=block_hash
        )
        if graph is None:
            raise ChainError(f"subnet {netuid} has no roster at block {block_hash}")
        if not isinstance(graph, dict):
            raise ChainError("invalid metagraph response")
        graph_netuid = _uint(graph.get("netuid"), 16, label="metagraph subnet ID")
        graph_block = _uint(graph.get("block"), 32, label="metagraph block")
        if graph_netuid != netuid or (block is not None and graph_block != block):
            raise ChainError("metagraph does not match the requested subnet and block")
        block = graph_block
        owner_hotkey = graph.get("owner_hotkey")
        if owner_hotkey is not None:
            owner_hotkey = _hotkey(owner_hotkey)

        count = _uint(graph.get("num_uids"), 16, label="metagraph UID count")
        hotkeys = graph.get("hotkeys")
        registrations = graph.get("block_at_registration")
        permits = graph.get("validator_permit")
        if any(
            not isinstance(column, list) or len(column) != count
            for column in (hotkeys, registrations, permits)
        ):
            raise ChainError("metagraph roster columns do not match the UID count")

        slots = []
        seen_hotkeys = set()
        validator_hotkeys = set()
        # The SDK's SCALE codec renders AccountId32 values in SS58 form.
        for uid, (address, registration, permit) in enumerate(zip(hotkeys, registrations, permits)):
            hotkey = _hotkey(address)
            registered_at = _uint(registration, 32, label="registration block")
            if registered_at > block or type(permit) is not bool:
                raise ChainError(f"invalid registration block or permit for UID {uid}")
            if hotkey in seen_hotkeys:
                raise ChainError("metagraph contains a duplicate hotkey")
            seen_hotkeys.add(hotkey)
            slots.append(MinerSlot(uid, hotkey, registered_at))
            if permit:
                validator_hotkeys.add(hotkey)
    except ReportError as error:
        raise ChainError(str(error)) from error

    snapshot = ChainSnapshot(genesis_hash, netuid, block, block_hash, tuple(slots), owner_hotkey)
    return Roster(snapshot, frozenset(validator_hotkeys))
