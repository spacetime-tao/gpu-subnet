"""Store an unverified scores response with its body, headers, and trailers."""

import base64
import binascii
import hashlib
import json
import os
import tempfile
from dataclasses import dataclass
from pathlib import Path

from .evidence import MAX_INPUT_BYTES, _bounded_integer, _fields, _non_integer, _unique_object, read_bounded

_MAX_HEADER_BYTES = 128 * 1024
_MAX_ENCODED_BODY_BYTES = 4 * ((MAX_INPUT_BYTES + 2) // 3)
_MAX_CAPTURE_BYTES = _MAX_ENCODED_BODY_BYTES + _MAX_HEADER_BYTES + 256


class CaptureError(ValueError):
    """The response cannot be stored or the capture cannot be loaded."""


@dataclass(frozen=True, slots=True)
class ScoreResponse:
    status: int
    headers: tuple[tuple[str, str], ...]
    body: bytes
    trailers: tuple[tuple[str, str], ...] = ()

    def __post_init__(self) -> None:
        if type(self.status) is not int or self.status != 200:
            raise CaptureError("a scores capture requires HTTP status 200")
        if not isinstance(self.body, bytes) or len(self.body) > MAX_INPUT_BYTES:
            raise CaptureError("response body must be bytes within the input size limit")
        _validate_pairs(self.headers, "headers")
        _validate_pairs(self.trailers, "trailers")
        field_bytes = len(_json_bytes(self.headers))
        if self.trailers:
            field_bytes += len(_json_bytes(self.trailers))
        if field_bytes > _MAX_HEADER_BYTES:
            raise CaptureError("response headers and trailers exceed the capture size limit")

    @property
    def body_sha256(self) -> str:
        return hashlib.sha256(self.body).hexdigest()


def _json_bytes(value: object) -> bytes:
    return json.dumps(value, ensure_ascii=True, separators=(",", ":")).encode("ascii")


def _validate_pairs(pairs: object, label: str) -> None:
    if not isinstance(pairs, tuple) or any(
        not isinstance(pair, tuple)
        or len(pair) != 2
        or not isinstance(pair[0], str)
        or not pair[0]
        or not isinstance(pair[1], str)
        for pair in pairs
    ):
        raise CaptureError(f"response {label} must be ordered name and value pairs")


def _load_pairs(pairs: object, label: str) -> tuple[tuple[str, str], ...]:
    if not isinstance(pairs, list) or any(not isinstance(pair, list) for pair in pairs):
        raise CaptureError(f"response {label} must be ordered name and value pairs")
    return tuple(tuple(pair) for pair in pairs)


def save_capture(path: Path, response: ScoreResponse) -> None:
    """Publish a complete private capture without replacing an existing file."""
    bundle = {
        "version": 2 if response.trailers else 1,
        "status": response.status,
        "headers": response.headers,
        "body_base64": base64.b64encode(response.body).decode("ascii"),
    }
    if response.trailers:
        bundle["trailers"] = response.trailers
    raw = _json_bytes(bundle)
    descriptor, temporary_path = tempfile.mkstemp(prefix=".scores-capture-", dir=path.parent)
    try:
        with os.fdopen(descriptor, "wb") as output:
            output.write(raw)
            output.write(b"\n")
        os.link(temporary_path, path)
    finally:
        Path(temporary_path).unlink()


def load_capture(path: Path) -> ScoreResponse:
    """Recover the body bytes and response fields for offline analysis."""
    try:
        raw = read_bounded(path, _MAX_CAPTURE_BYTES)
        bundle = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=_unique_object,
            parse_int=_bounded_integer,
            parse_float=_non_integer,
            parse_constant=_non_integer,
        )
        fields = {"version", "status", "headers", "body_base64"}
        if isinstance(bundle, dict) and bundle.get("version") == 2:
            fields.add("trailers")
        bundle = _fields(bundle, fields, label="response capture")
    except (ValueError, RecursionError) as error:
        raise CaptureError("invalid or oversized response capture JSON") from error

    if type(bundle["version"]) is not int or bundle["version"] not in (1, 2):
        raise CaptureError("unsupported response capture version")
    headers = _load_pairs(bundle["headers"], "headers")
    trailers = _load_pairs(bundle["trailers"], "trailers") if bundle["version"] == 2 else ()

    encoded_body = bundle["body_base64"]
    if not isinstance(encoded_body, str) or len(encoded_body) > _MAX_ENCODED_BODY_BYTES:
        raise CaptureError("invalid or oversized encoded response body")
    try:
        body = base64.b64decode(encoded_body, validate=True)
    except (ValueError, binascii.Error) as error:
        raise CaptureError("response body must use standard base64") from error

    return ScoreResponse(bundle["status"], headers, body, trailers)
