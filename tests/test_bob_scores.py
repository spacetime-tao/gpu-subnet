import contextlib
import hashlib
import io
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from gpu_subnet import __main__ as validator
from gpu_subnet import scores
from gpu_subnet.bob_scores import fetch_bob_scores, load_bob_report
from gpu_subnet.evidence import ReportError
from gpu_subnet.scores_capture import ScoreResponse

ROOT = Path(__file__).resolve().parents[1]
NETUID = 42
WINDOW = {"start_ts": 1_731_700_000, "end_ts": 1_731_786_400}
SYNTHETIC_KEY = Ed25519PrivateKey.from_private_bytes(bytes(reversed(range(32))))
PIN = SYNTHETIC_KEY.public_key().public_bytes_raw().hex()


def signed_report(**overrides):
    payload = {"version": 1, "netuid": NETUID, "window": WINDOW, "scores": [], **overrides}
    # Non-canonical whitespace and UTF-8 catch accidental re-serialization.
    report = json.dumps(payload, ensure_ascii=False, indent=2) + "\n"
    return {
        "report": report,
        "sig": SYNTHETIC_KEY.sign(report.encode("utf-8")).hex(),
        "pubkey": PIN,
        "alg": "ed25519",
    }


def encoded(envelope):
    return json.dumps(envelope).encode("utf-8")


def row(hotkey, work, invalid=0):
    return {"hotkey": hotkey, "verified_work": work, "invalid_rate": invalid}


class BobReportTests(unittest.TestCase):
    def test_signature_covers_exact_text_and_future_fields_are_ignored(self):
        envelope = signed_report(extra={"café": 7.75}, scores=[
            {**row("miner-a", 5.5, 0.2), "chat": {"ttft_p50_s": None}},
        ])
        report = load_bob_report(encoded(envelope), PIN, netuid=NETUID)
        self.assertEqual(report.digest, hashlib.sha256(envelope["report"].encode("utf-8")).hexdigest())
        self.assertEqual(report.rows[0].work.numerator, 22)
        self.assertEqual(report.rows[0].work.denominator, 5)

        envelope["report"] = json.dumps(json.loads(envelope["report"]))
        with self.assertRaisesRegex(ReportError, "invalid scores report signature"):
            load_bob_report(encoded(envelope), PIN, netuid=NETUID)

    def test_signature_is_verified_before_parsing_inner_json(self):
        envelope = {**signed_report(), "report": "not JSON"}
        with self.assertRaisesRegex(ReportError, "invalid scores report signature"):
            load_bob_report(encoded(envelope), PIN, netuid=NETUID)

    def test_checks_signer_algorithm_version_subnet_and_window(self):
        envelopes = (
            ({**signed_report(), "alg": "other"}, "algorithm"),
            ({**signed_report(), "pubkey": "00" * 32}, "pinned pool key"),
            (signed_report(version=True), "version"),
            (signed_report(netuid=NETUID + 1), "different subnet"),
            (signed_report(window={**WINDOW, "end_ts": WINDOW["end_ts"] - 1}), "duration"),
        )
        for envelope, reason in envelopes:
            with self.subTest(reason=reason), self.assertRaisesRegex(ReportError, reason):
                load_bob_report(encoded(envelope), PIN, netuid=NETUID)

    def test_rejects_ambiguous_and_out_of_domain_fields(self):
        cases = (
            (row("miner-a", float("nan")), "finite"),
            (row("miner-a", -1), "verified_work"),
            (row("miner-a", 1, -0.25), "invalid_rate"),
            (row("miner-a", 1, 0.0000001), "six decimal places"),
        )
        for score, reason in cases:
            with self.subTest(score=score), self.assertRaisesRegex(ReportError, reason):
                load_bob_report(encoded(signed_report(scores=[score])), PIN, netuid=NETUID)

        envelope = signed_report()
        envelope["report"] = envelope["report"].replace('"version": 1', '"version": 2, "version": 1')
        envelope["sig"] = SYNTHETIC_KEY.sign(envelope["report"].encode("utf-8")).hex()
        with self.assertRaisesRegex(ReportError, "duplicate JSON field"):
            load_bob_report(encoded(envelope), PIN, netuid=NETUID)

    def test_fetch_rejects_origin_and_token_mistakes_before_opening(self):
        cases = (
            ("http://pool.example.invalid", "fake-token"),
            ("https://user:fake-password@pool.example.invalid", "fake-token"),
            ("https://pool.example.invalid/subnet/scores", "fake-token"),
            ("https://pool.example.invalid?token=fake-token", "fake-token"),
            ("https://pool.example.invalid", "Bearer fake-token"),
            ("https://pool.example.invalid", ""),
        )
        with patch("gpu_subnet.bob_scores.fetch_scores") as fetch:
            for base, token in cases:
                with self.subTest(base=base, token=token), self.assertRaises(ReportError):
                    fetch_bob_scores(base, token, netuid=NETUID)
            fetch.assert_not_called()

    def test_capture_and_offline_replay_use_bearer_and_apply_exact_dust_threshold(self):
        raw = encoded(signed_report(scores=[
            row("miner-a", 99_989, 0.9),        # 9,998.9 eligible work
            row("miner-b", 0.6),
            row("miner-b", 0.4),               # exactly one basis point
            row("miner-c", 0.1),
            row("unregistered", 100_000),
            row("owner", 100_000),
        ]))
        with tempfile.TemporaryDirectory() as directory:
            directory = Path(directory)
            capture_path = directory / "capture.json"
            snapshot_path = directory / "snapshot.json"
            key_path = directory / "pool.hex"
            snapshot = json.loads((ROOT / "examples/snapshot.json").read_bytes())
            snapshot["owner_hotkey"] = "owner"
            snapshot_path.write_text(json.dumps(snapshot))
            key_path.write_text(PIN)

            stdout = io.StringIO()
            with (
                patch.dict(os.environ, {"SCORES_TOKEN": "fake-token"}),
                patch("gpu_subnet.bob_scores.fetch_scores", return_value=ScoreResponse(200, (), raw)) as fetch,
                contextlib.redirect_stdout(stdout),
            ):
                status = scores.main([
                    "capture", "--api-base", "https://pool.example.invalid/", "--netuid", str(NETUID),
                    "--output", str(capture_path),
                ])
            self.assertEqual(status, 0)
            fetch.assert_called_once_with(
                "https://pool.example.invalid/subnet/scores?netuid=42&window=86400",
                headers={"Authorization": "Bearer fake-token"}, timeout=30.0,
            )
            self.assertNotIn("fake-token", capture_path.read_text())
            self.assertEqual(json.loads(stdout.getvalue())["status"], "unverified_capture")

            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                status = validator.main([
                    "--format", "bob-v1", "--capture", str(capture_path), "--snapshot", str(snapshot_path),
                    "--pool-public-key", str(key_path),
                ])
            self.assertEqual(status, 0)
            weights = json.loads(stdout.getvalue())["normalized_weights"]
            self.assertEqual(set(weights), {"7", "12"})
            self.assertAlmostEqual(weights["12"], 1 / 9_999.9)
            self.assertAlmostEqual(sum(weights.values()), 1.0)
