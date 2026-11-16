import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from gpu_subnet import scores
from gpu_subnet.scores_capture import (
    _MAX_HEADER_BYTES,
    CaptureError,
    ScoreResponse,
    load_capture,
    save_capture,
)


class CaptureTrailerTests(unittest.TestCase):
    def setUp(self):
        directory = self.enterContext(tempfile.TemporaryDirectory())
        self.path = Path(directory) / "capture.json"
        self.headers = (("Digest", "fixture-header-digest"),)
        self.trailers = (
            ("Digest", "fixture-trailer-digest"),
            ("X-Proof", "fixture-proof-one"),
            ("X-Proof", "fixture-proof-two"),
        )

    def test_capture_round_trips_trailers_separately_in_version_two(self):
        response = ScoreResponse(200, self.headers, b"\x80payload", self.trailers)
        save_capture(self.path, response)
        stored = json.loads(self.path.read_bytes())
        self.assertEqual(stored["version"], 2)
        self.assertEqual(stored["headers"], [list(pair) for pair in self.headers])
        self.assertEqual(stored["trailers"], [list(pair) for pair in self.trailers])
        self.assertEqual(load_capture(self.path), response)

    def test_version_one_stays_readable_and_remains_default_without_trailers(self):
        self.path.write_text(
            '{"version":1,"status":200,"headers":[["Digest","fixture-header-digest"]],'
            '"body_base64":"YWJj"}\n',
            encoding="utf-8",
        )
        response = load_capture(self.path)
        self.assertEqual(response, ScoreResponse(200, self.headers, b"abc"))

        second = self.path.with_name("resaved.json")
        save_capture(second, response)
        self.assertEqual(second.read_bytes(), self.path.read_bytes())

    def test_capture_field_sections_share_one_size_limit(self):
        header = ("X", "a" * (_MAX_HEADER_BYTES - len(b'[["X",""]]')))
        save_capture(self.path, ScoreResponse(200, (header,), b""))
        self.assertEqual(load_capture(self.path).headers, (header,))

        with self.assertRaisesRegex(CaptureError, "capture size limit"):
            ScoreResponse(200, (header,), b"", self.trailers)

    def test_invalid_trailer_field_shapes_are_rejected(self):
        save_capture(self.path, ScoreResponse(200, self.headers, b"", self.trailers))
        valid = json.loads(self.path.read_bytes())
        for trailers in ({"Digest": "proof"}, [["Digest"]], [["Digest", 100]], [["", "proof"]]):
            with self.subTest(trailers=trailers):
                self.path.write_text(json.dumps(valid | {"trailers": trailers}), encoding="utf-8")
                with self.assertRaisesRegex(CaptureError, "trailers must be ordered name and value pairs"):
                    load_capture(self.path)

    def test_inspect_reports_trailer_names_only(self):
        save_capture(self.path, ScoreResponse(200, self.headers, b"fixture-body", self.trailers))
        output = io.StringIO()
        with patch("gpu_subnet.scores.fetch_scores") as fetch, contextlib.redirect_stdout(output):
            rc = scores.main(["inspect", "--input", str(self.path)])
        self.assertEqual(rc, 0)
        fetch.assert_not_called()
        self.assertEqual(json.loads(output.getvalue())["trailers"], ["Digest", "X-Proof", "X-Proof"])
        self.assertNotIn("fixture-", output.getvalue())
