import stat
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from threading import Barrier

from gpu_subnet.journal import JournalError, SubmissionJournal


def attempt(tag: str, **changes) -> dict:
    return {
        "extrinsic_hash": "0x" + tag * 64,
        "nonce": 42,
        "genesis_hash": "0x" + "b" * 64,
        "netuid": 1,
        "mechid": 0,
        "validator_hotkey": "validator",
        "start_block": 10,
        "end_block": 20,
        "end_block_hash": "0x" + "a" * 64,
        "report_digest": "c" * 64,
        "encoded_weights": {3: 65_535},
        "targets": [{"uid": 3, "hotkey": "miner", "registered_at": 2}],
        "scan_start_block": 21,
        "broadcast_head_block": 22,
        "transaction_period_blocks": 8,
    } | changes


def inclusion(status: str, finalized_block: int, **changes) -> dict:
    return {
        "status": status,
        "finalized_block": finalized_block,
        "inclusion_block": 22,
        "inclusion_block_hash": "0x" + "d" * 64,
    } | changes


class JournalTests(unittest.TestCase):
    def setUp(self):
        directory = Path(self.enterContext(tempfile.TemporaryDirectory()))
        self.path = directory / "submissions.sqlite3"
        self.journal = SubmissionJournal(self.path)

    def test_attempt_and_results_survive_opening_a_new_journal_instance(self):
        record = attempt("1")
        tx_hash = record["extrinsic_hash"]
        self.journal.record_attempt(record)
        reopened = SubmissionJournal(self.path)
        self.assertEqual(stat.S_IMODE(self.path.stat().st_mode), 0o600)
        self.assertEqual(reopened.get(tx_hash), {
            "attempt": record | {"encoded_weights": {"3": 65_535}},
            "receipt": None,
            "readback": None,
        })
        self.journal.save_receipt(tx_hash, {"status": "commit_queued", "success": True})
        self.journal.save_readback(tx_hash, {"status": "reveal_applied"})
        result = reopened.get(tx_hash)
        self.assertEqual(result["receipt"]["status"], "commit_queued")
        self.assertEqual(result["readback"]["status"], "reveal_applied")

    def test_unresolved_window_rejects_different_report_with_same_end(self):
        first = attempt("1")
        self.journal.record_attempt(first)
        self.journal.save_receipt(first["extrinsic_hash"], {"status": "submission_unconfirmed"})
        with self.assertRaisesRegex(JournalError, "already reserved"):
            self.journal.record_attempt(attempt("2", start_block=11, report_digest="d" * 64))
        self.journal.record_attempt(attempt("3", start_block=11, end_block=21))
        with self.assertRaisesRegex(JournalError, "already recorded"):
            self.journal.record_attempt(first)

    def test_verified_failure_allows_retry_and_keeps_attempt_history(self):
        first, retry = attempt("1"), attempt("2", nonce=43)
        self.journal.record_attempt(first)
        self.journal.save_readback(first["extrinsic_hash"], {"status": "dispatch_failed"})
        self.journal.save_readback(first["extrinsic_hash"], {"status": "awaiting_finality"})
        self.journal.record_attempt(retry)
        self.assertEqual(
            self.journal.get(first["extrinsic_hash"])["readback"]["status"], "dispatch_failed"
        )
        self.assertIsNone(self.journal.get(retry["extrinsic_hash"])["readback"])
        with self.assertRaisesRegex(JournalError, "already reserved"):
            self.journal.record_attempt(attempt("3"))

    def test_rejects_older_windows_in_the_same_chain_subnet_mechanism_and_validator(self):
        newer = attempt("1", end_block=21)
        self.journal.record_attempt(newer)
        self.journal.save_readback(newer["extrinsic_hash"], inclusion("reveal_applied", 30))

        with self.assertRaisesRegex(JournalError, "before reserved window 21"):
            SubmissionJournal(self.path).record_attempt(attempt("2"))
        self.journal.record_attempt(attempt("3", genesis_hash="0x" + "e" * 64))
        self.journal.record_attempt(attempt("4", netuid=2))
        self.journal.record_attempt(attempt("5", mechid=1))
        self.journal.record_attempt(attempt("6", validator_hotkey="another-validator"))
        self.journal.record_attempt(attempt("7", end_block=22))

    def test_submission_slot_coordinates_one_hotkey_across_subnets(self):
        slot = {
            "genesis_hash": "0x" + "b" * 64, "netuid": 1, "mechid": 0,
            "hotkey": "validator", "end_block": 20,
        }
        reopened = SubmissionJournal(self.path)
        with self.journal.submission_slot(**slot):
            with self.assertRaisesRegex(JournalError, "another weight submission is active"):
                with reopened.submission_slot(**(slot | {"netuid": 2, "mechid": 1})):
                    self.fail("the same hotkey acquired the slot twice")
            with reopened.submission_slot(**(slot | {"hotkey": "different-validator"})):
                reopened.record_attempt(attempt("2", validator_hotkey="different-validator"))

    def test_submission_slot_waits_for_complete_expiry_across_subnets(self):
        record = attempt("1")
        tx_hash = record["extrinsic_hash"]
        self.journal.record_attempt(record)
        self.journal.save_receipt(tx_hash, {"status": "submission_unconfirmed", "success": False})
        reopened = SubmissionJournal(self.path)
        slot = {
            "genesis_hash": record["genesis_hash"], "netuid": 2, "mechid": 0,
            "hotkey": record["validator_hotkey"], "end_block": 21,
        }
        for readback in (
            {"status": "awaiting_finality", "finalized_block": 29},
            {"status": "expired_unseen", "finalized_block": 30},
        ):
            self.journal.save_readback(tx_hash, readback)
            with self.assertRaisesRegex(JournalError, f"reconcile unresolved submission {tx_hash} on subnet 1"):
                with reopened.submission_slot(**slot):
                    self.fail("the unresolved hotkey acquired a slot")
        with reopened.submission_slot(**(slot | {"hotkey": "other"})):
            pass
        with reopened.submission_slot(**(slot | {"genesis_hash": "0x" + "e" * 64})):
            pass

        self.journal.save_readback(tx_hash, {
            "status": "expired_unseen", "finalized_block": 30,
            "scan_start_block": 21, "scan_end_block": 30, "expiry_upper_bound": 30,
        })
        with reopened.submission_slot(**slot):
            pass

    def test_submission_slot_accepts_durable_finality_or_definitive_rejection(self):
        for index, (receipt, readback) in enumerate((
            ({"status": "commit_queued", "success": True,
              "block_hash": "0x" + "d" * 64, "extrinsic_id": "22-0004"}, None),
            ({"status": "submission_failed", "success": False}, None),
            (None, inclusion("dispatch_failed", 23, extrinsic_id="22-0004")),
            (None, inclusion("inclusion_verified", 23, extrinsic_id="22-0004")),
        )):
            with self.subTest(receipt=receipt, readback=readback):
                hotkey = f"validator-{index}"
                record = attempt(str(index), validator_hotkey=hotkey)
                self.journal.record_attempt(record)
                if receipt is not None:
                    self.journal.save_receipt(record["extrinsic_hash"], receipt)
                if readback is not None:
                    self.journal.save_readback(record["extrinsic_hash"], readback)
                with self.journal.submission_slot(
                    genesis_hash=record["genesis_hash"], netuid=1, mechid=0,
                    hotkey=hotkey, end_block=21,
                ):
                    pass

    def test_failed_reservation_allows_retries_only_at_the_latest_window(self):
        first = attempt("1", end_block=21)
        self.journal.record_attempt(first)
        self.journal.save_readback(first["extrinsic_hash"], inclusion("dispatch_failed", 24))

        with self.assertRaisesRegex(JournalError, "before reserved window 21"):
            self.journal.record_attempt(attempt("2"))
        self.journal.record_attempt(attempt("3", end_block=21, nonce=43))

    def test_positive_receipt_blocks_retry_even_with_conflicting_readback(self):
        first = attempt("1")
        tx_hash = first["extrinsic_hash"]
        self.journal.record_attempt(first)
        succeeded = {"status": "commit_queued", "submission": {"success": True}}
        self.journal.save_receipt(tx_hash, succeeded)
        self.journal.save_readback(tx_hash, {"status": "expired_unseen"})
        self.journal.save_receipt(tx_hash, {"status": "submission_unconfirmed"})
        self.assertEqual(self.journal.get(tx_hash)["receipt"], succeeded)
        with self.assertRaisesRegex(JournalError, "already reserved"):
            self.journal.record_attempt(attempt("2"))

    def test_unconfirmed_receipt_can_be_retried_after_verified_expiry(self):
        first = attempt("1")
        tx_hash = first["extrinsic_hash"]
        self.journal.record_attempt(first)
        self.journal.save_receipt(tx_hash, {"status": "submission_unconfirmed", "success": True})
        with self.assertRaisesRegex(JournalError, "already reserved"):
            self.journal.record_attempt(attempt("2"))
        self.journal.save_readback(tx_hash, {"status": "expired_unseen"})
        self.journal.record_attempt(attempt("2"))

    def test_confirmed_application_survives_later_inconclusive_readback(self):
        first = attempt("1")
        tx_hash = first["extrinsic_hash"]
        self.journal.record_attempt(first)
        self.journal.save_readback(tx_hash, {"status": "weights_applied"})
        self.journal.save_readback(tx_hash, {"status": "inclusion_unconfirmed"})
        self.assertEqual(self.journal.get(tx_hash)["readback"]["status"], "weights_applied")

    def test_conflicting_absence_cannot_free_a_window_after_recovered_inclusion(self):
        first = attempt("1")
        tx_hash = first["extrinsic_hash"]
        self.journal.record_attempt(first)
        pending = inclusion("commit_pending", 23)
        self.journal.save_readback(tx_hash, pending)
        self.journal.save_readback(tx_hash, {"status": "expired_unseen", "finalized_block": 34})

        reopened = SubmissionJournal(self.path)
        entry = reopened.get(tx_hash)
        self.assertIsNone(entry["receipt"])
        saved = entry["readback"]
        self.assertEqual(saved["status"], "inclusion_unconfirmed")
        self.assertIs(saved["inclusion_conflict"], True)
        self.assertEqual(saved["inclusion_block_hash"], pending["inclusion_block_hash"])
        self.assertEqual(saved["inclusion_block"], pending["inclusion_block"])
        self.assertEqual(saved["finalized_block"], 34)
        with self.assertRaisesRegex(JournalError, "already reserved"):
            reopened.record_attempt(attempt("2"))

        applied = inclusion("reveal_applied", 35)
        reopened.save_readback(tx_hash, applied)
        self.assertEqual(reopened.get(tx_hash)["readback"], applied)
        reopened.record_attempt(attempt("3", end_block=21))

    def test_older_inclusion_replaces_a_contradictory_complete_scan(self):
        first = attempt("1")
        tx_hash = first["extrinsic_hash"]
        self.journal.record_attempt(first)
        self.journal.save_readback(tx_hash, {"status": "expired_unseen", "finalized_block": 34})
        pending = inclusion("commit_pending", 23)
        self.journal.save_readback(tx_hash, pending)

        saved = self.journal.get(tx_hash)["readback"]
        self.assertIs(saved["inclusion_conflict"], True)
        self.assertEqual(saved["inclusion_block_hash"], pending["inclusion_block_hash"])
        self.assertEqual(saved["finalized_block"], 34)
        with self.assertRaisesRegex(JournalError, "already reserved"):
            self.journal.record_attempt(attempt("2"))

    def test_older_reads_can_fill_missing_evidence_without_regressing_finalized_height(self):
        first = attempt("1")
        tx_hash = first["extrinsic_hash"]
        self.journal.record_attempt(first)
        self.journal.save_readback(tx_hash, {"status": "awaiting_finality", "finalized_block": 25})
        self.journal.save_readback(tx_hash, inclusion("inclusion_unconfirmed", 24))
        self.assertEqual(self.journal.get(tx_hash)["readback"], inclusion("inclusion_unconfirmed", 25))

        self.journal.save_readback(tx_hash, inclusion("commit_pending", 23))
        self.assertEqual(self.journal.get(tx_hash)["readback"], inclusion("commit_pending", 25))
        self.journal.save_readback(tx_hash, inclusion("reveal_unconfirmed", 26))
        self.journal.save_readback(tx_hash, inclusion("commit_pending", 24))
        self.assertEqual(self.journal.get(tx_hash)["readback"], inclusion("reveal_unconfirmed", 26))

    def test_inconclusive_dispatch_cannot_erase_known_success_before_a_conflicting_failure(self):
        first = attempt("1")
        tx_hash = first["extrinsic_hash"]
        self.journal.record_attempt(first)
        self.journal.save_readback(tx_hash, inclusion("commit_pending", 23))
        self.journal.save_readback(tx_hash, inclusion("inclusion_unconfirmed", 24))
        self.journal.save_readback(tx_hash, inclusion("dispatch_failed", 25))

        saved = self.journal.get(tx_hash)["readback"]
        self.assertIs(saved["dispatch_success"], True)
        self.assertIs(saved["inclusion_conflict"], True)
        self.assertEqual(saved["conflicting_readback"]["status"], "dispatch_failed")
        with self.assertRaisesRegex(JournalError, "already reserved"):
            self.journal.record_attempt(attempt("2"))

    def test_conflict_preserves_known_failure_against_later_conflicting_success(self):
        first = attempt("1")
        tx_hash = first["extrinsic_hash"]
        self.journal.record_attempt(first)
        self.journal.save_readback(tx_hash, inclusion("dispatch_failed", 23))
        self.journal.save_readback(tx_hash, {"status": "expired_unseen", "finalized_block": 34})
        self.journal.save_readback(tx_hash, inclusion("weights_applied", 35))

        saved = self.journal.get(tx_hash)["readback"]
        self.assertIs(saved["dispatch_success"], False)
        self.assertIs(saved["inclusion_conflict"], True)
        self.assertEqual(saved["finalized_block"], 35)
        with self.assertRaisesRegex(JournalError, "already reserved"):
            self.journal.record_attempt(attempt("2"))

    def test_list_returns_public_identifiers_without_weights_or_targets(self):
        first, other_subnet = attempt("1"), attempt("2", netuid=2)
        self.journal.record_attempt(first)
        self.journal.record_attempt(other_subnet)
        self.journal.save_receipt(first["extrinsic_hash"], {
            "status": "commit_queued", "submission": {"success": True, "weights": [10, 90]},
        })
        self.journal.save_readback(first["extrinsic_hash"], {"status": "commit_pending"})
        summary = self.journal.list_attempts(netuid=1)
        self.assertEqual(summary, [{
            key: first[key] for key in (
                "extrinsic_hash", "genesis_hash", "netuid", "mechid", "validator_hotkey",
                "start_block", "end_block", "broadcast_head_block",
            )
        } | {"receipt_status": "commit_queued", "readback_status": "commit_pending"}])
        self.assertEqual(self.journal.list_attempts(limit=1)[0]["netuid"], 2)

    def test_concurrent_writers_for_same_window_get_one_reservation(self):
        ready = Barrier(2)

        def record(tag):
            journal = SubmissionJournal(self.path)
            ready.wait(timeout=5)
            try:
                journal.record_attempt(attempt(tag))
            except JournalError as error:
                return str(error)
            return "recorded"

        with ThreadPoolExecutor(max_workers=2) as workers:
            outcomes = list(workers.map(record, ("1", "2")))
        self.assertEqual(outcomes.count("recorded"), 1)
        self.assertTrue(next(outcome for outcome in outcomes if outcome != "recorded").startswith(
            "scoring window is already reserved by "
        ))
        self.assertEqual(len(self.journal.list_attempts()), 1)

    def test_refuses_nonprivate_and_symlink_destinations(self):
        alias = self.path.with_name("journal-alias.sqlite3")
        alias.symlink_to(self.path)
        with self.assertRaises(JournalError):
            SubmissionJournal(alias)
        self.path.chmod(0o640)
        with self.assertRaises(JournalError):
            SubmissionJournal(self.path)

    def test_invalid_attempt_does_not_reserve_window(self):
        with self.assertRaises(JournalError):
            self.journal.record_attempt(attempt("1", nonce=None))
        with self.assertRaises(JournalError):
            self.journal.record_attempt(attempt("1", extra=object()))
        self.journal.record_attempt(attempt("1"))
