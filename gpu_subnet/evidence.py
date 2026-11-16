"""Verify the pilot work report envelope and deserialize its claims."""

import hashlib
import json
import re
from dataclasses import dataclass
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey


MAX_INPUT_BYTES = 8 * 1024 * 1024


def read_bounded(path: Path, limit: int) -> bytes:
    with path.open("rb") as source:
        data = source.read(limit + 1)
    if len(data) > limit:
        raise ValueError(f"{path} exceeds the {limit}-byte input limit")
    return data


class ReportError(ValueError):
    """A report cannot be authenticated or interpreted."""


@dataclass(frozen=True, slots=True)
class MinerWork:
    hotkey: str
    registered_at: int
    accepted_work: int


@dataclass(frozen=True, slots=True)
class WorkReport:
    genesis_hash: str
    netuid: int
    start_block: int
    end_block: int
    end_block_hash: str
    miners: tuple[MinerWork, ...]
    digest: str


def canonical_payload(payload: dict[str, object]) -> bytes:
    """Encode version 1 payload bytes for signing and verification."""
    return json.dumps(
        payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False
    ).encode("ascii")


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ReportError("duplicate JSON field")
        result[key] = value
    return result


def _bounded_integer(value: str) -> int:
    if len(value.removeprefix("-")) > 20:
        raise ReportError("JSON integer exceeds the supported range")
    return int(value)


def _non_integer(_value: str) -> None:
    raise ReportError("JSON numbers must be integers")


def _read_json(raw: bytes) -> object:
    if len(raw) > MAX_INPUT_BYTES:
        raise ReportError("JSON document exceeds 8 MiB")
    try:
        return json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=_unique_object,
            parse_int=_bounded_integer,
            parse_float=_non_integer,
            parse_constant=_non_integer,
        )
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as exc:
        raise ReportError("invalid UTF-8 JSON document") from exc


def _fields(value: object, expected: set[str], *, label: str) -> dict[str, object]:
    if not isinstance(value, dict) or value.keys() != expected:
        field_list = ", ".join(sorted(expected))
        raise ReportError(f"{label} requires exactly these fields ({field_list})")
    return value


def _uint(value: object, bits: int, *, label: str) -> int:
    if type(value) is not int or not 0 <= value < 2**bits:
        raise ReportError(f"{label} must be an unsigned {bits}-bit integer")
    return value


def _chain_hash(value: object, *, label: str) -> str:
    if not isinstance(value, str) or re.fullmatch(r"0x[0-9a-f]{64}", value) is None:
        raise ReportError(f"{label} must be a lowercase 32-byte hex hash with a 0x prefix")
    return value


def _hotkey(value: object) -> str:
    if not isinstance(value, str) or re.fullmatch(r"[!-~]{1,128}", value) is None:
        raise ReportError("hotkey must contain 1 to 128 printable non-space ASCII characters")
    return value


def _hex_bytes(value: object, size: int, *, label: str) -> bytes:
    if not isinstance(value, str) or re.fullmatch(rf"[0-9a-f]{{{2 * size}}}", value) is None:
        raise ReportError(f"{label} must be {size} bytes of lowercase hex without a prefix")
    return bytes.fromhex(value)


def load_report(raw: bytes, public_key_hex: str) -> WorkReport:
    """Authenticate a report against a pool key supplied by the operator."""
    public_key = Ed25519PublicKey.from_public_bytes(
        _hex_bytes(public_key_hex, 32, label="pool public key")
    )
    envelope = _fields(_read_json(raw), {"payload", "signature"}, label="report envelope")
    payload = _fields(
        envelope["payload"],
        {
            "version",
            "genesis_hash",
            "netuid",
            "start_block",
            "end_block",
            "end_block_hash",
            "miners",
        },
        label="report payload",
    )
    if type(payload["version"]) is not int or payload["version"] != 1:
        raise ReportError("unsupported report version")
    genesis_hash = _chain_hash(payload["genesis_hash"], label="genesis_hash")
    netuid = _uint(payload["netuid"], 16, label="netuid")
    start_block = _uint(payload["start_block"], 32, label="start_block")
    end_block = _uint(payload["end_block"], 32, label="end_block")
    if start_block >= end_block:
        raise ReportError("start_block must precede end_block")
    end_block_hash = _chain_hash(payload["end_block_hash"], label="end_block_hash")
    raw_miners = payload["miners"]
    if not isinstance(raw_miners, list):
        raise ReportError("miners must be a JSON array")

    miners = []
    seen_hotkeys: set[str] = set()
    for value in raw_miners:
        row = _fields(value, {"hotkey", "registered_at", "accepted_work"}, label="miner row")
        hotkey = _hotkey(row["hotkey"])
        if hotkey in seen_hotkeys:
            raise ReportError("duplicate miner hotkey")
        seen_hotkeys.add(hotkey)
        miners.append(
            MinerWork(
                hotkey=hotkey,
                registered_at=_uint(row["registered_at"], 32, label="registered_at"),
                accepted_work=_uint(row["accepted_work"], 64, label="accepted_work"),
            )
        )

    signed_bytes = canonical_payload(payload)
    signature = _hex_bytes(envelope["signature"], 64, label="report signature")
    try:
        public_key.verify(signature, signed_bytes)
    except InvalidSignature as exc:
        raise ReportError("invalid report signature") from exc

    return WorkReport(
        genesis_hash=genesis_hash,
        netuid=netuid,
        start_block=start_block,
        end_block=end_block,
        end_block_hash=end_block_hash,
        miners=tuple(miners),
        digest=hashlib.sha256(signed_bytes).hexdigest(),
    )
