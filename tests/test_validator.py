import hashlib
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from gpu_subnet.evidence import ReportError, load_report
from gpu_subnet.weights import WeightError, load_snapshot, preview_weights


GENESIS_HASH = "0x" + "01" * 32
END_BLOCK_HASH = "0x" + "02" * 32
OTHER_HASH = "0x" + "03" * 32
WINDOW_BLOCKS = 20


def encode_json(value):
    return json.dumps(
        value, ensure_ascii=True, sort_keys=True, separators=(",", ":"), allow_nan=False
    ).encode("ascii")


class ValidatorPreviewTests(unittest.TestCase):
    def setUp(self):
        # This key is a public test fixture and must never be used outside the tests.
        self.pool_key = Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
        self.public_key = self.pool_key.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        ).hex()
        self.payload = {
            "version": 1,
            "genesis_hash": GENESIS_HASH,
            "netuid": 7,
            "start_block": 100,
            "end_block": 120,
            "end_block_hash": END_BLOCK_HASH,
            "miners": [
                {"hotkey": "miner-a", "registered_at": 75, "accepted_work": 35},
                {"hotkey": "miner-b", "registered_at": 105, "accepted_work": 12},
            ],
        }
        self.snapshot = {
            "genesis_hash": GENESIS_HASH,
            "netuid": 7,
            "block": 120,
            "block_hash": END_BLOCK_HASH,
            "miners": [
                {"uid": 9, "hotkey": "miner-a", "registered_at": 75},
                {"uid": 2, "hotkey": "miner-b", "registered_at": 105},
            ],
        }

    def sign(self, payload):
        signature = self.pool_key.sign(encode_json(payload)).hex()
        # Keep the envelope readable. The signature covers canonical payload bytes.
        return json.dumps({"payload": payload, "signature": signature}, indent=2).encode("ascii")

    def preview(self):
        report = load_report(self.sign(self.payload), self.public_key)
        snapshot = load_snapshot(encode_json(self.snapshot))
        return preview_weights(report, snapshot, WINDOW_BLOCKS)

    def test_signed_window_previews_exact_weights_ordered_by_uid(self):
        report = load_report(self.sign(self.payload), self.public_key)
        self.assertEqual(report.digest, hashlib.sha256(encode_json(self.payload)).hexdigest())
        self.assertEqual(list(self.preview().items()), [(2, 12), (9, 35)])

    def test_tampering_invalidates_pool_signature(self):
        signed = json.loads(self.sign(self.payload))
        signed["payload"]["miners"][0]["accepted_work"] = 99
        with self.assertRaises(ReportError):
            load_report(encode_json(signed), self.public_key)

    def test_report_requires_the_configured_pool_key(self):
        other_key = Ed25519PrivateKey.from_private_bytes(b"\x01" * 32)
        other_public_key = other_key.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        ).hex()
        with self.assertRaises(ReportError):
            load_report(self.sign(self.payload), other_public_key)

    def test_duplicate_hotkeys_rejected_even_in_a_validly_signed_report(self):
        self.payload["miners"][1]["hotkey"] = self.payload["miners"][0]["hotkey"]
        with self.assertRaises(ReportError):
            load_report(self.sign(self.payload), self.public_key)

    def test_duplicate_json_keys_rejected_even_if_last_value_matches_signature(self):
        signed = self.sign(self.payload).replace(b'"netuid": 7', b'"netuid": 9, "netuid": 7')
        with self.assertRaises(ReportError):
            load_report(signed, self.public_key)

    def test_invalid_work_units_rejected_even_with_a_valid_signature(self):
        for value in (True, -1, 12.5, "12", 1 << 64):
            with self.subTest(value=value):
                self.payload["miners"][0]["accepted_work"] = value
                with self.assertRaises(ReportError):
                    load_report(self.sign(self.payload), self.public_key)

    def test_wrong_chain_subnet_block_hash_or_window_rejected(self):
        for field, value in (
            ("genesis_hash", OTHER_HASH),
            ("netuid", 8),
            ("start_block", 101),
            ("end_block", 119),
            ("end_block_hash", OTHER_HASH),
        ):
            with self.subTest(field=field):
                payload = self.payload | {field: value}
                report = load_report(self.sign(payload), self.public_key)
                snapshot = load_snapshot(encode_json(self.snapshot))
                with self.assertRaises(WeightError):
                    preview_weights(report, snapshot, WINDOW_BLOCKS)

    def test_recycled_uid_and_reregistered_hotkey_do_not_inherit_work(self):
        self.snapshot["miners"] = [
            {"uid": 9, "hotkey": "replacement", "registered_at": 115},
            {"uid": 3, "hotkey": "miner-a", "registered_at": 116},
            {"uid": 8, "hotkey": "miner-b", "registered_at": 105},
        ]
        self.assertEqual(self.preview(), {8: 12})

    def test_duplicate_snapshot_uid_rejected(self):
        self.snapshot["miners"][1]["uid"] = self.snapshot["miners"][0]["uid"]
        with self.assertRaises(WeightError):
            load_snapshot(encode_json(self.snapshot))

    def test_offline_cli_accepts_roster_export_with_permit_metadata(self):
        self.snapshot["validator_hotkeys"] = ["miner-b"]
        result = self.run_cli(self.sign(self.payload))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout)["weights"], {"2": 12, "9": 35})

    def test_snapshot_rejects_invalid_permit_metadata_and_unknown_fields(self):
        for metadata in (
            {"validator_hotkeys": "miner-b"},
            {"validator_hotkeys": ["miner-a", "miner-a"]},
            {"validator_hotkeys": ["unknown"]},
            {"validator_hotkeys": [None]},
            {"unknown": []},
        ):
            with self.subTest(metadata=metadata), self.assertRaises(WeightError):
                load_snapshot(encode_json(self.snapshot | metadata))

    def test_missing_miner_in_report_does_not_receive_a_weight(self):
        self.snapshot["miners"].append({"uid": 1, "hotkey": "miner-c", "registered_at": 90})
        self.assertEqual(self.preview(), {2: 12, 9: 35})

    def test_zero_work_and_empty_reports_produce_empty_previews(self):
        zero_rows = [row | {"accepted_work": 0} for row in self.payload["miners"]]
        for rows in ([], zero_rows):
            with self.subTest(number_of_rows=len(rows)):
                self.payload["miners"] = rows
                self.assertEqual(self.preview(), {})

    def run_cli(self, signed_report):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            report_path = root / "report.json"
            report_path.write_bytes(signed_report)
            snapshot_path = root / "snapshot.json"
            snapshot_path.write_bytes(encode_json(self.snapshot))
            key_path = root / "pool-key.hex"
            key_path.write_text(self.public_key + "\n", encoding="ascii")
            return subprocess.run(
                [
                    sys.executable, "-m", "gpu_subnet",
                    "--report", str(report_path),
                    "--snapshot", str(snapshot_path),
                    "--pool-public-key", str(key_path),
                    "--window-blocks", str(WINDOW_BLOCKS),
                ],
                capture_output=True,
                text=True,
                timeout=10,
                check=False,
            )

    def test_cli_emits_json_preview(self):
        result = self.run_cli(self.sign(self.payload))
        self.assertEqual(result.returncode, 0, result.stderr)
        preview = json.loads(result.stdout)
        self.assertEqual(preview["mode"], "offline_preview")
        self.assertEqual(preview["status"], "preview_ready")
        self.assertEqual(preview["weights"], {"2": 12, "9": 35})

    def test_cli_distinguishes_invalid_evidence_from_verified_zero_work(self):
        self.payload["miners"] = []
        signed_report = self.sign(self.payload)
        empty = self.run_cli(signed_report)
        self.assertEqual(empty.returncode, 0, empty.stderr)
        preview = json.loads(empty.stdout)
        self.assertEqual(preview["status"], "no_eligible_work")
        self.assertEqual(preview["weights"], {})

        tampered = signed_report.replace(b'"netuid": 7', b'"netuid": 9')
        invalid = self.run_cli(tampered)
        self.assertEqual(invalid.returncode, 2)
        self.assertEqual(invalid.stdout, "")
        self.assertTrue(invalid.stderr.strip())
