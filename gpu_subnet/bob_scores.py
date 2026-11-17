"""Fetch and interpret the Bob Labs v1 scores contract."""

import hashlib
import json
import re
from dataclasses import dataclass
from decimal import Context, Decimal, DecimalException, Inexact
from fractions import Fraction
from urllib.parse import urlencode, urlsplit

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .evidence import (
    MAX_INPUT_BYTES,
    ReportError,
    _bounded_integer,
    _hex_bytes,
    _hotkey,
    _uint,
    _unique_object,
)
from .scores_capture import ScoreResponse
from .scores_http import fetch_scores
from .weights import ChainSnapshot

DEFAULT_WINDOW_SECONDS = 86_400
_MICRO = 1_000_000
_MAX_WORK = (1 << 64) - 1


@dataclass(frozen=True, slots=True)
class BobScore:
    hotkey: str
    work: Fraction


@dataclass(frozen=True, slots=True)
class BobReport:
    netuid: int
    start_ts: int
    end_ts: int
    rows: tuple[BobScore, ...]
    digest: str


def _check_request(netuid: int, window_seconds: int) -> None:
    if _uint(netuid, 16, label="netuid") == 0:
        raise ReportError("scores require a non-root netuid")
    if _uint(window_seconds, 64, label="window length") == 0:
        raise ReportError("scores window length must be positive")


def fetch_bob_scores(
    api_base: str, token: str, *, netuid: int, window_seconds: int = DEFAULT_WINDOW_SECONDS,
    timeout: float = 30.0,
) -> ScoreResponse:
    """Fetch one report using the pool's HTTPS origin and a separate bearer token."""
    _check_request(netuid, window_seconds)
    if not isinstance(api_base, str) or re.search(r"[\x00-\x20\x7f\\?#]", api_base):
        raise ReportError("API_BASE must be a HTTPS origin without a path, query or fragment")
    try:
        base = urlsplit(api_base)
    except ValueError:
        raise ReportError("API_BASE must be a valid HTTPS origin") from None
    if (
        base.scheme != "https"
        or not base.hostname
        or base.username is not None
        or base.path not in ("", "/")
    ):
        raise ReportError("API_BASE must be a HTTPS origin without credentials or a path")
    if not isinstance(token, str) or not re.fullmatch(r"[A-Za-z0-9._~+/\-]+=*", token):
        raise ReportError("SCORES_TOKEN must contain a valid bearer token")
    query = urlencode({"netuid": netuid, "window": window_seconds})
    url = f"https://{base.netloc}/subnet/scores?{query}"
    return fetch_scores(url, headers={"Authorization": f"Bearer {token}"}, timeout=timeout)


def _reject_nonfinite(_value: str) -> None:
    raise ReportError("Bob Labs JSON numbers must be finite")


def _json(raw: bytes) -> object:
    if len(raw) > MAX_INPUT_BYTES:
        raise ReportError("Bob Labs report exceeds 8 MiB")
    try:
        return json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=_unique_object,
            parse_int=_bounded_integer,
            parse_float=Decimal,
            parse_constant=_reject_nonfinite,
        )
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError, DecimalException):
        raise ReportError("invalid Bob Labs UTF-8 JSON document") from None


def _object(value: object, required: set[str], label: str) -> dict[str, object]:
    if not isinstance(value, dict) or not required <= value.keys():
        raise ReportError(f"{label} requires {', '.join(sorted(required))}")
    return value


def _hex(value: object, size: int, label: str) -> bytes:
    return _hex_bytes(value.lower() if isinstance(value, str) else value, size, label=label)


def _micros(value: object, maximum: int, label: str) -> int:
    if type(value) not in (int, Decimal) or not 0 <= value <= maximum:
        raise ReportError(f"{label} must be a number in [0, {maximum}]")
    # Quantize with an explicit context so even tiny excess digits are rejected
    # instead of being silently rounded away by the ambient decimal context.
    context = Context(prec=26, traps=[Inexact])
    try:
        fixed = Decimal(value).quantize(Decimal("0.000001"), context=context)
    except Inexact:
        raise ReportError(f"{label} must have at most six decimal places") from None
    return int(fixed.scaleb(6, context=context))


def load_bob_report(
    raw: bytes, public_key_hex: str, *, netuid: int, window_seconds: int = DEFAULT_WINDOW_SECONDS,
) -> BobReport:
    """Verify the exact UTF-8 report string before reading its contents."""
    _check_request(netuid, window_seconds)
    pin = _hex(public_key_hex, 32, "pool public key")
    envelope = _object(_json(raw), {"report", "sig", "pubkey", "alg"}, "scores envelope")
    if envelope["alg"] != "ed25519":
        raise ReportError("unsupported scores signature algorithm")
    if _hex(envelope["pubkey"], 32, "envelope public key") != pin:
        raise ReportError("scores signing key does not match the pinned pool key")
    if not isinstance(envelope["report"], str):
        raise ReportError("scores envelope report must be a JSON string")
    try:
        signed = envelope["report"].encode("utf-8")
    except UnicodeEncodeError:
        raise ReportError("scores report must be valid UTF-8") from None
    signature = _hex(envelope["sig"], 64, "scores signature")
    try:
        Ed25519PublicKey.from_public_bytes(pin).verify(signature, signed)
    except InvalidSignature:
        raise ReportError("invalid scores report signature") from None

    report = _object(_json(signed), {"version", "netuid", "window", "scores"}, "scores report")
    if type(report["version"]) is not int or report["version"] != 1:
        raise ReportError("unsupported scores report version")
    if _uint(report["netuid"], 16, label="report netuid") != netuid:
        raise ReportError("the scores report is for a different subnet")
    window = _object(report["window"], {"start_ts", "end_ts"}, "scores window")
    start_ts = _uint(window["start_ts"], 64, label="window start_ts")
    end_ts = _uint(window["end_ts"], 64, label="window end_ts")
    if end_ts - start_ts != window_seconds:
        raise ReportError("scores window duration does not match the requested window")
    if not isinstance(report["scores"], list):
        raise ReportError("scores must be an array")

    rows = []
    for value in report["scores"]:
        row = _object(value, {"hotkey", "verified_work", "invalid_rate"}, "scores row")
        work = _micros(row["verified_work"], _MAX_WORK, "verified_work")
        invalid = _micros(row["invalid_rate"], 1, "invalid_rate")
        hotkey = _hotkey(row["hotkey"])
        discounted_work = Fraction(work * (_MICRO - invalid), _MICRO**2)
        rows.append(BobScore(hotkey, discounted_work))
    return BobReport(netuid, start_ts, end_ts, tuple(rows), hashlib.sha256(signed).hexdigest())


def preview_bob_weights(
    report: BobReport, snapshot: ChainSnapshot, *, validator_hotkey: str | None = None,
) -> dict[int, Fraction]:
    """Score registered hotkeys, then drop weights strictly below one basis point."""
    if report.netuid != snapshot.netuid:
        raise ReportError("scores report and roster belong to different subnets")
    if snapshot.owner_hotkey is None:
        raise ReportError("the roster must identify the subnet owner hotkey")

    eligible = {
        slot.hotkey: slot.uid
        for slot in snapshot.miners
        if slot.hotkey not in (snapshot.owner_hotkey, validator_hotkey)
    }
    weights: dict[int, Fraction] = {}
    for row in report.rows:
        if row.work > 0 and row.hotkey in eligible:
            uid = eligible[row.hotkey]
            weights[uid] = weights.get(uid, 0) + row.work
    total = sum(weights.values())
    return {uid: work for uid, work in sorted(weights.items()) if 10_000 * work >= total}


def normalized_weights(weights: dict[int, Fraction]) -> dict[int, float]:
    """Convert exact weights into relative shares for the preview receipt."""
    total = sum(weights.values())
    return {uid: float(work / total) for uid, work in weights.items()}
