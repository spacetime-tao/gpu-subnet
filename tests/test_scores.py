import contextlib
import hashlib
import io
import json
import os
import socket
import stat
import tempfile
import unittest
from email.message import Message
from http.client import HTTPSConnection
from pathlib import Path
from unittest.mock import Mock, patch
from urllib.error import HTTPError, URLError

from gpu_subnet import __main__ as validator
from gpu_subnet import scores
from gpu_subnet.scores_capture import CaptureError, ScoreResponse, load_capture, save_capture
from gpu_subnet.scores_http import ScoreFetchError, fetch_scores


URL = "https://pool.example.invalid/subnet/scores?netuid=7"
BODY = b'{ "scores": [] }\r\n'
RESPONSE_HEADERS = (
    ("Content-Type", "application/json"),
    ("X-Scores-Signature", "fixture-signature"),
    ("x-scores-signature", "other-signature"),
)
SAMPLE = ScoreResponse(200, RESPONSE_HEADERS, BODY)


class FakeHTTPResponse:
    def __init__(self, body=BODY, headers=RESPONSE_HEADERS, status=200):
        self.status = status
        self.version = 11
        self.headers = Message()
        self.trailers = ()
        for name, value in headers:
            self.headers[name] = value
        self.read = Mock(side_effect=io.BytesIO(body).read)

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        pass


class ScoresFetchTests(unittest.TestCase):
    def setUp(self):
        self.response = FakeHTTPResponse()
        self.opener = Mock()
        self.opener.open.return_value = self.response
        self.build_opener = self.enterContext(
            patch("gpu_subnet.scores_http.build_opener", return_value=self.opener)
        )

    def test_get_preserves_exact_body_and_ordered_duplicate_headers(self):
        result = fetch_scores(URL, headers={"Authorization": "Bearer fake-token"}, timeout=2.5)
        self.assertEqual(result, SAMPLE)
        self.opener.open.assert_called_once()
        request = self.opener.open.call_args.args[0]
        self.assertEqual(request.full_url, URL)
        self.assertEqual(request.get_method(), "GET")
        self.assertEqual(request.get_header("Authorization"), "Bearer fake-token")
        self.assertEqual(request.get_header("Accept-encoding"), "identity")
        self.assertEqual(self.opener.open.call_args.kwargs["timeout"], 2.5)

    def test_streamed_body_larger_than_limit_is_rejected_even_without_length(self):
        with patch("gpu_subnet.scores_http.MAX_INPUT_BYTES", 8):
            with self.assertRaises(ScoreFetchError):
                fetch_scores(URL)
        self.assertEqual(self.response.read.call_args.args[0], 9)

    def test_declared_size_larger_than_limit_is_rejected_before_reading_body(self):
        self.response.headers["Content-Length"] = "9"
        with patch("gpu_subnet.scores_http.MAX_INPUT_BYTES", 8):
            with self.assertRaises(ScoreFetchError):
                fetch_scores(URL)
        self.response.read.assert_not_called()

    def test_truncated_response_is_rejected(self):
        self.response.headers["Content-Length"] = str(len(BODY) + 1)
        with self.assertRaises(ScoreFetchError):
            fetch_scores(URL)

    def test_single_chunked_response_preserves_decoded_body_and_header(self):
        self.response.headers["Transfer-Encoding"] = "Chunked"
        result = fetch_scores(URL)
        self.assertEqual(result.body, BODY)
        self.assertIn(("Transfer-Encoding", "Chunked"), result.headers)

    def test_unsupported_transfer_encodings_are_rejected_before_reading(self):
        for values in (["gzip"], ["gzip, chunked"], ["chunked", "chunked"], ["chunked "], [""]):
            with self.subTest(values=values):
                headers = RESPONSE_HEADERS + tuple(("Transfer-Encoding", value) for value in values)
                response = FakeHTTPResponse(headers=headers)
                self.opener.open.return_value = response
                with self.assertRaisesRegex(ScoreFetchError, "unsupported Transfer-Encoding"):
                    fetch_scores(URL)
                response.read.assert_not_called()

    def test_chunked_response_with_content_length_is_rejected(self):
        self.response.headers["Transfer-Encoding"] = "chunked"
        self.response.headers["Content-Length"] = str(len(BODY))
        with self.assertRaisesRegex(ScoreFetchError, "conflicting length headers"):
            fetch_scores(URL)
        self.response.read.assert_not_called()

    def test_redirects_are_blocked_and_do_not_disclose_credentials(self):
        private_url = URL + "&key=private-query-token"
        redirect = "https://other.example.invalid/private-location"
        headers = Message()
        headers["Location"] = redirect
        self.opener.open.side_effect = HTTPError(
            private_url, 302, "server-secret", headers, io.BytesIO(b"secret-body")
        )

        with self.assertRaises(ScoreFetchError) as caught:
            fetch_scores(private_url, headers={"Authorization": "Bearer secret-header"})

        message = str(caught.exception)
        self.assertIn("302", message)
        for secret in ("private-query-token", "private-location", "server-secret", "secret-header"):
            self.assertNotIn(secret, message)
        self.opener.open.assert_called_once()
        handlers = self.build_opener.call_args.args
        redirect_handler = next(handler for handler in handlers if hasattr(handler, "redirect_request"))
        self.assertIsNone(
            redirect_handler.redirect_request(Mock(), None, 302, "Found", headers, redirect)
        )

    def test_malformed_urls_and_headers_are_rejected_before_opening(self):
        for url in (
            "http://pool.example.invalid/subnet/scores",
            "https://user:password@pool.example.invalid/subnet/scores",
            f"{URL}#fragment",
            "https:///subnet/scores",
            f"{URL}\r\nX-Fault: true",
        ):
            with self.subTest(url=url), self.assertRaises(ScoreFetchError):
                fetch_scores(url)
        for headers in (
            {"Bad Header": "token"},
            {"Authorization": "Bearer x\r\nInjected: true"},
            {"accept-encoding": "gzip"},
        ):
            with self.subTest(headers=headers), self.assertRaises(ScoreFetchError):
                fetch_scores(URL, headers=headers)
        self.opener.open.assert_not_called()

    def test_unexpected_status_and_timeout_are_safe_errors(self):
        self.response.status = 503
        with self.assertRaises(ScoreFetchError):
            fetch_scores(URL)
        self.response.read.assert_not_called()
        self.opener.open.side_effect = URLError(TimeoutError("private network details"))
        with self.assertRaises(ScoreFetchError) as caught:
            fetch_scores(URL)
        self.assertNotIn("private network details", str(caught.exception))
        with self.assertRaises(ScoreFetchError):
            fetch_scores(URL, timeout=0)


class ScoresWireTests(unittest.TestCase):
    def setUp(self):
        for owner, name in (
            (socket.socket, "connect"), (socket.socket, "connect_ex"), (socket, "getaddrinfo"),
        ):
            self.enterContext(patch.object(
                owner, name, side_effect=AssertionError("network access in offline HTTP check"),
            ))
        self.enterContext(patch("urllib.request.getproxies", return_value={}))

    def response_context(self, wire):
        # Run the HTTPS handler and actual HTTPResponse over an in-memory wire.
        peer = Mock()
        peer.makefile.return_value = io.BytesIO(wire)

        def connect(connection):
            connection.sock = peer

        return patch.object(HTTPSConnection, "connect", connect)

    def test_chunked_body_and_duplicate_trailers_survive_the_https_handler(self):
        wire = (
            b"HTTP/1.1 100 Continue\r\nX-Interim: discard\r\n\r\n"
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: Chunked\r\nX-Proof: initial\r\n\r\n"
            b'3 ;tag = "x;y"\r\na\xffc\r\n2;next=yes\r\n\r\n\r\n'
            b"0\r\nX-Proof: first\r\nx-proof: second\r\n\r\n"
        )
        with self.response_context(wire):
            result = fetch_scores(URL)
        self.assertEqual(result.body, b"a\xffc\r\n")
        self.assertEqual(result.headers, (("Transfer-Encoding", "Chunked"), ("X-Proof", "initial")))
        self.assertEqual(result.trailers, (("X-Proof", "first"), ("x-proof", "second")))

    def test_malformed_header_lines_are_rejected(self):
        for wire in (
            b"HTTP/1.1 +200 OK\r\nContent-Length: 0\r\n\r\n",
            b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n",
            b"HTTP/1.1 200 OK\nContent-Length: 0\n\n",
            b"HTTP/1.1 200 OK\r\nBad-Header\r\nContent-Length: 100\r\n\r\nabc",
            b"HTTP/1.1 200 OK\r\nContent-Length:\r\n 0\r\n\r\n",
            b"HTTP/1.1 200 OK\r\nContent-Length : 0\r\n\r\n",
            b"HTTP/1.1 200 OK\r\nX-Proof: secret\x00value\r\n\r\n",
        ):
            with self.subTest(wire=wire), self.response_context(wire):
                with self.assertRaises(ScoreFetchError) as caught:
                    fetch_scores(URL)
                self.assertNotIn("secret", str(caught.exception))

    def test_malformed_chunked_framing_is_rejected(self):
        head = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"
        for framing in (
            b"3\r\nabczz0\r\n\r\n",
            b"3\r\nabc\r\n0\r\n",
            b"3\r\nabc\r\n0",
            b"+3\r\nabc\r\n0\r\n\r\n",
            b"0x3\r\nabc\r\n0\r\n\r\n",
            b"3;tag=\"unterminated\r\nabc\r\n0\r\n\r\n",
            b"3\r\na",
            b"0\r\nMalformed-Trailer\r\n\r\n",
            b"0\r\nContent-Length: 1\r\n\r\n",
        ):
            with self.subTest(framing=framing), self.response_context(head + framing):
                with self.assertRaises(ScoreFetchError):
                    fetch_scores(URL)


class ScoresCaptureTests(unittest.TestCase):
    def setUp(self):
        self.directory = Path(self.enterContext(tempfile.TemporaryDirectory()))
        self.path = self.directory / "capture.json"

    def test_private_capture_round_trips_exact_bytes_and_header_pairs(self):
        binary = ScoreResponse(200, RESPONSE_HEADERS, b"\r\n\x00\xff\xc3\xa9")
        save_capture(self.path, binary)
        self.assertEqual(stat.S_IMODE(self.path.stat().st_mode), 0o600)
        self.assertEqual(load_capture(self.path), binary)
        self.assertEqual(load_capture(self.path).body_sha256, hashlib.sha256(binary.body).hexdigest())

    def test_existing_capture_survives_failed_overwrite(self):
        save_capture(self.path, SAMPLE)
        with self.assertRaises(FileExistsError):
            save_capture(self.path, ScoreResponse(200, RESPONSE_HEADERS, b"replacement"))
        self.assertEqual(load_capture(self.path), SAMPLE)
        self.assertEqual(list(self.directory.iterdir()), [self.path])

    def test_malformed_capture_bundles_are_rejected(self):
        save_capture(self.path, SAMPLE)
        valid = json.loads(self.path.read_bytes())
        for field, value in (
            ("version", 99),
            ("status", 302),
            ("headers", [{"Content-Type": "application/json"}]),
            ("body_base64", "not!base64"),
            ("unrecognized", True),
        ):
            with self.subTest(field=field, value=value):
                self.path.write_text(json.dumps(valid | {field: value}), encoding="utf-8")
                with self.assertRaises(CaptureError):
                    load_capture(self.path)
        self.path.write_bytes(b'{"version":1,"version":1,' + json.dumps(valid).encode("utf-8")[1:])
        with self.assertRaises(CaptureError):
            load_capture(self.path)


class ScoresCommandTests(unittest.TestCase):
    def test_capture_and_local_inspect_keep_response_contents_off_stdout(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "capture.json"
            output = io.StringIO()
            with (
                patch.dict(os.environ, {"SCORES_TEST_AUTH": "Bearer private-test-token"}),
                patch("gpu_subnet.scores.fetch_scores", return_value=SAMPLE) as fetch,
                contextlib.redirect_stdout(output),
            ):
                rc = scores.main([
                    "capture", "--url", URL, "--output", str(path),
                    "--header-env", "Authorization=SCORES_TEST_AUTH", "--timeout", "2",
                ])

            self.assertEqual(rc, 0)
            fetch.assert_called_once_with(
                URL, headers={"authorization": "Bearer private-test-token"}, timeout=2.0,
            )
            self.assertNotIn("private-test-token", output.getvalue())
            self.assertNotIn("fixture-signature", output.getvalue())
            receipt = json.loads(output.getvalue())
            self.assertEqual(receipt["status"], "unverified_capture")
            self.assertEqual(receipt["body_bytes"], len(BODY))
            self.assertEqual(receipt["body_sha256"], hashlib.sha256(BODY).hexdigest())
            self.assertEqual(load_capture(path), SAMPLE)

            with (
                patch("gpu_subnet.scores.fetch_scores") as fetch,
                contextlib.redirect_stdout(io.StringIO()) as inspected,
            ):
                rc = scores.main(["inspect", "--input", str(path)])
            self.assertEqual(rc, 0)
            self.assertEqual(json.loads(inspected.getvalue())["body_sha256"], receipt["body_sha256"])
            fetch.assert_not_called()

    def test_capture_refuses_existing_destination_before_fetch(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "capture.json"
            save_capture(path, SAMPLE)
            with (
                patch("gpu_subnet.scores.fetch_scores") as fetch,
                contextlib.redirect_stderr(io.StringIO()),
            ):
                rc = scores.main(["capture", "--url", URL, "--output", str(path)])
            self.assertNotEqual(rc, 0)
            fetch.assert_not_called()
            self.assertEqual(load_capture(path), SAMPLE)

    def test_local_replay_uses_the_existing_prototype_signature_checks(self):
        examples = Path(__file__).resolve().parent.parent / "examples"
        report = examples / "report.json"
        common_args = [
            "--snapshot", str(examples / "snapshot.json"),
            "--pool-public-key", str(examples / "pool-public-key.hex"),
            "--window-blocks", "100",
        ]
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            capture = root / "capture.json"
            save_capture(capture, ScoreResponse(200, RESPONSE_HEADERS, report.read_bytes()))
            with contextlib.redirect_stdout(io.StringIO()) as raw_preview:
                self.assertEqual(validator.main(["--report", str(report), *common_args]), 0)
            with contextlib.redirect_stdout(io.StringIO()) as captured_preview:
                self.assertEqual(validator.main(["--capture", str(capture), *common_args]), 0)
            self.assertEqual(json.loads(captured_preview.getvalue()), json.loads(raw_preview.getvalue()))
            self.assertEqual(json.loads(captured_preview.getvalue())["weights"], {"7": 700, "12": 300})

            altered = root / "altered.json"
            altered_body = report.read_bytes().replace(b'"accepted_work": 700', b'"accepted_work": 900')
            save_capture(altered, ScoreResponse(200, RESPONSE_HEADERS, altered_body))
            with contextlib.redirect_stderr(io.StringIO()) as stderr:
                self.assertEqual(validator.main(["--capture", str(altered), *common_args]), 2)
            self.assertIn("signature", stderr.getvalue())
