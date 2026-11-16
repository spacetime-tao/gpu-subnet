"""Read a single scores response while preserving its body, headers, and trailers."""

import re
from http.client import HTTPException, HTTPResponse, HTTPSConnection
from urllib.error import HTTPError
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, HTTPSHandler, Request, build_opener

from .evidence import MAX_INPUT_BYTES
from .scores_capture import ScoreResponse, _MAX_HEADER_BYTES

_TOKEN = r"[!#$%&'*+.^_`|~0-9A-Za-z-]+"
_HEADER_NAME = re.compile(_TOKEN)
_FIELD_VALUE = re.compile(r"[\t\x20-\x7e\x80-\xff]*")
_STATUS_LINE = re.compile(rb"HTTP/[0-9]\.[0-9] [0-9]{3}(?: [\t\x20-\x7e\x80-\xff]*)?")
_QUOTED_EXTENSION = rb'"(?:[\t \x21\x23-\x5b\x5d-\x7e\x80-\xff]|\\[\t \x21-\x7e\x80-\xff])*"'
_CHUNK_SIZE_LINE = re.compile(
    rb"([0-9A-Fa-f]+)(?:[ \t]*;[ \t]*" + _TOKEN.encode("ascii")
    + rb"(?:[ \t]*=[ \t]*(?:" + _TOKEN.encode("ascii") + b"|" + _QUOTED_EXTENSION + rb"))?)*"
)
_HTTP_LINE_LIMIT = 65_537
_RESERVED_HEADERS = {
    "accept", "accept-encoding", "connection", "content-length", "expect", "host",
    "keep-alive", "proxy-authorization", "proxy-connection", "te", "trailer",
    "transfer-encoding", "upgrade",
}
_FORBIDDEN_TRAILERS = _RESERVED_HEADERS | {
    "authorization", "content-encoding", "content-range", "content-type",
    "proxy-authenticate", "www-authenticate",
}


class ScoreFetchError(ValueError):
    """A scores request failed or returned an unusable HTTP response."""


class _NoRedirects(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def _read_http_line(source, section: str, limit: int = _HTTP_LINE_LIMIT) -> bytes:
    line = source.readline(limit)
    if len(line) >= limit or not line.endswith(b"\r\n"):
        raise ScoreFetchError(f"scores response has an incomplete or malformed {section} line")
    return line


def _field_pair(line: bytes) -> tuple[str, str]:
    name, colon, value = line[:-2].decode("iso-8859-1").partition(":")
    if not colon or not _HEADER_NAME.fullmatch(name) or not _FIELD_VALUE.fullmatch(value):
        raise ScoreFetchError("scores response has a malformed header or trailer field")
    return name, value.lstrip(" \t")


class _ResponseHead:
    """Check the wire lines that the standard response parser would normalize."""

    def __init__(self, source):
        self.source = source
        self.size = 0
        self.at_status = True

    def readline(self, limit):
        line = _read_http_line(self.source, "response header", limit)
        self.size += len(line)
        if self.size > _MAX_HEADER_BYTES:
            raise ScoreFetchError("scores response headers exceed the capture size limit")
        if self.at_status:
            if not _STATUS_LINE.fullmatch(line[:-2]):
                raise ScoreFetchError("scores response has a malformed HTTP status line")
        elif line != b"\r\n":
            _field_pair(line)
        # An interim response ends its own header block before the next status.
        self.at_status = line == b"\r\n"
        return line

    def close(self):
        self.source.close()


class _CaptureHTTPResponse(HTTPResponse):
    trailers: tuple[tuple[str, str], ...] = ()

    def begin(self):
        if self.headers is not None:
            return
        source = self.fp
        self.fp = _ResponseHead(source)
        try:
            super().begin()
        finally:
            if self.fp is not None:
                self.fp = source

    def _get_chunk_left(self):
        if self.chunk_left == 0:
            if self._safe_read(2) != b"\r\n":
                raise ScoreFetchError("scores response has an invalid chunk terminator")
            self.chunk_left = None
        return super()._get_chunk_left()

    def _read_next_chunk_size(self):
        line = _read_http_line(self.fp, "chunk size")
        match = _CHUNK_SIZE_LINE.fullmatch(line[:-2])
        if match is None:
            raise ScoreFetchError("scores response has an invalid chunk size or extension")
        size = int(match[1], 16)
        if size > MAX_INPUT_BYTES:
            raise ScoreFetchError("scores response exceeds the body size limit")
        return size

    def _read_and_discard_trailer(self):
        pairs = []
        total = 0
        while True:
            line = _read_http_line(self.fp, "chunk trailer")
            if line == b"\r\n":
                self.trailers = tuple(pairs)
                return
            total += len(line)
            if total > _MAX_HEADER_BYTES:
                raise ScoreFetchError("scores response trailers exceed the capture size limit")
            name, value = _field_pair(line)
            if name.lower() in _FORBIDDEN_TRAILERS:
                raise ScoreFetchError("scores response uses a forbidden trailer field")
            pairs.append((name, value))


class _CaptureHTTPSConnection(HTTPSConnection):
    response_class = _CaptureHTTPResponse


class _CaptureHTTPSHandler(HTTPSHandler):
    def https_open(self, request):
        return self.do_open(_CaptureHTTPSConnection, request, context=self._context)


def fetch_scores(
    url: str, *, headers: dict[str, str] | None = None, timeout: float = 30.0
) -> ScoreResponse:
    """Fetch an operator-selected HTTPS endpoint once and retain the response bytes."""
    if (
        not isinstance(url, str)
        or not url.isascii()
        or re.search(r"[\x00-\x20\x7f\\#]", url)
    ):
        raise ScoreFetchError("scores URL must be an absolute HTTPS URL")
    try:
        endpoint = urlsplit(url)
        port = endpoint.port
    except ValueError:
        raise ScoreFetchError("scores URL must be an absolute HTTPS URL") from None
    if (
        endpoint.scheme != "https"
        or not endpoint.hostname
        or endpoint.username is not None
        or port == 0
        or "%" in endpoint.netloc
    ):
        raise ScoreFetchError("scores URL must be an absolute HTTPS URL without credentials")
    if type(timeout) not in (float, int) or not 0 < timeout < float("inf"):
        raise ScoreFetchError("scores request timeout must be positive and finite")

    request_headers = {"Accept": "application/json", "Accept-Encoding": "identity"}
    seen_names = set(_RESERVED_HEADERS)
    for name, value in (headers or {}).items():
        if not isinstance(name, str) or not _HEADER_NAME.fullmatch(name):
            raise ScoreFetchError("invalid scores request header name")
        if name.lower() in seen_names:
            raise ScoreFetchError("duplicate or reserved scores request header")
        if not isinstance(value, str) or not re.fullmatch(r"[\x20-\x7e]+", value):
            raise ScoreFetchError("invalid scores request header value")
        seen_names.add(name.lower())
        request_headers[name] = value

    request = Request(url, headers=request_headers, method="GET")
    try:
        with build_opener(_NoRedirects(), _CaptureHTTPSHandler()).open(request, timeout=timeout) as response:
            if response.status != 200:
                raise ScoreFetchError(f"scores endpoint returned HTTP {response.status}")
            if response.headers.defects:
                raise ScoreFetchError("scores response has malformed headers")
            expected_length = _content_length(response.headers.get_all("Content-Length", []))
            transfer_encodings = response.headers.get_all("Transfer-Encoding", [])
            if transfer_encodings:
                if expected_length is not None:
                    raise ScoreFetchError("scores response has conflicting length headers")
                # http.client only removes framing for one exact chunked coding.
                if response.version < 11 or [encoding.lower() for encoding in transfer_encodings] != ["chunked"]:
                    raise ScoreFetchError("scores response has unsupported Transfer-Encoding")
            body = response.read(MAX_INPUT_BYTES + 1)
            if len(body) > MAX_INPUT_BYTES:
                raise ScoreFetchError("scores response exceeds the body size limit")
            if expected_length is not None and len(body) != expected_length:
                raise ScoreFetchError("scores response body does not match Content-Length")
            return ScoreResponse(response.status, tuple(response.headers.raw_items()), body, response.trailers)
    except ScoreFetchError:
        raise
    except HTTPError as error:
        error.close()
        raise ScoreFetchError(f"scores endpoint returned HTTP {error.code}") from None
    except (OSError, HTTPException, ValueError, OverflowError):
        raise ScoreFetchError("scores request failed") from None


def _content_length(values: list[str]) -> int | None:
    if not values:
        return None
    lengths = {value.strip() for value in values}
    if len(lengths) != 1:
        raise ScoreFetchError("scores response has conflicting Content-Length headers")
    length = lengths.pop()
    if not re.fullmatch(r"[0-9]+", length):
        raise ScoreFetchError("scores response has an invalid Content-Length")
    length = length.lstrip("0") or "0"
    if len(length) > len(str(MAX_INPUT_BYTES)) or int(length) > MAX_INPUT_BYTES:
        raise ScoreFetchError("scores response exceeds the body size limit")
    return int(length)
