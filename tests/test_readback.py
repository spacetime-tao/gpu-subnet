import asyncio
import unittest
from hashlib import blake2b
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

from gpu_subnet.chain import _run_command
from gpu_subnet.journal import JournalError, SubmissionJournal
from gpu_subnet.readback import reconcile_submission
from gpu_subnet.roster import ChainError


def block_hash(number):
    return f"0x{number:064x}"


def block_height(hash_value):
    return int(hash_value, 16)


TX_HASH = "0x" + "ca" * 32
NETUID = 27
HOTKEY = "validator"
CIPHERTEXT = b"mock-commit"
COMMIT_HASH = "0x" + blake2b(CIPHERTEXT, digest_size=32).hexdigest()


def event(name, attributes=None, module="SubtensorModule"):
    return {"event": {"module_id": module, "event_id": name, "attributes": attributes}}


def entry(receipt=None, readback=None):
    return {
        "attempt": {
            "extrinsic_hash": TX_HASH,
            "nonce": 1,
            "genesis_hash": block_hash(0),
            "netuid": NETUID,
            "mechid": 0,
            "validator_hotkey": HOTKEY,
            "start_block": 180,
            "end_block": 200,
            "end_block_hash": block_hash(200),
            "report_digest": "ce" * 32,
            "scan_start_block": 201,
            "broadcast_head_block": 204,
            "transaction_period_blocks": 8,
            "encoded_weights": {"1": 43_690, "2": 65_535},
            "targets": [
                {"uid": 1, "hotkey": "first-miner", "registered_at": 20},
                {"uid": 2, "hotkey": "second-miner", "registered_at": 42},
            ],
        },
        "receipt": receipt,
        "readback": readback,
    }


class MockChain:
    def __init__(self, finalized=206):
        self._substrate = self
        self.finalized = finalized
        self.find_calls = []
        self.queue_lookups = []
        self.extrinsics = {}
        self.event_decode_error = None
        self.events_by_height = {}
        self.at_height = {}
        self.stored_weights = [(1, 43_690), (2, 65_535)]
        self.hotkeys = [HOTKEY, "first-miner", "second-miner"]
        self.registered_at = [12, 20, 42]

    def put_extrinsic(self, height, events, success=True):
        self.extrinsics[height] = SimpleNamespace(
            block_hash=block_hash(height),
            extrinsic_id=f"{height}-0002",
            events=events,
            success=success,
            message="simulated outcome",
        )

    async def finalized_block(self):
        return self.finalized

    async def block_hash(self, number):
        if number > self.finalized:
            raise AssertionError("test attempted to read an unfinalized block")
        return block_hash(number)

    async def find_extrinsic(self, hash_value, at, *, on_match=None):
        if hash_value != TX_HASH:
            raise AssertionError("readback looked for a different transaction")
        height = block_height(at)
        self.find_calls.append(height)
        extrinsic = self.extrinsics.get(height)
        if extrinsic is not None:
            if on_match is not None:
                on_match(height, int(extrinsic.extrinsic_id.partition("-")[2]))
            if self.event_decode_error is not None:
                raise self.event_decode_error
        return extrinsic

    async def query(self, module, storage, keys, *, block_hash):
        if (module, storage, keys) == ("SubtensorModule", "Weights", [NETUID, 0]):
            return self.stored_weights
        if (module, storage, keys) == ("SubtensorModule", "Uids", [NETUID, HOTKEY]):
            return 0
        raise AssertionError("readback queried unrelated storage")

    async def query_map(self, module, storage, keys, *, block_hash):
        if (module, storage, keys) != ("SubtensorModule", "TimelockedWeightCommits", [NETUID]):
            raise AssertionError("readback queried unrelated queue")
        number = block_height(block_hash)
        self.queue_lookups.append(number)
        prior = [height for height in self.at_height if height <= number]
        return self.at_height[max(prior)] if prior else []

    async def runtime_call(self, api, method, params, *, block_hash):
        if (api, method, params) != ("SubnetInfoRuntimeApi", "get_metagraph", [NETUID]):
            raise AssertionError("readback queried unrelated runtime API")
        return {
            "netuid": NETUID,
            "block": block_height(block_hash),
            "num_uids": 3,
            "hotkeys": self.hotkeys,
            "block_at_registration": self.registered_at,
            "validator_permit": [True, False, False],
        }

    async def events(self, at):
        return self.events_by_height.get(block_height(at), [])


class ReadbackTests(unittest.IsolatedAsyncioTestCase):
    async def _run_reconcile(self, path, client):
        args = SimpleNamespace(
            command="reconcile", journal=path, tx_hash=TX_HASH, netuid=NETUID, network="offline",
        )
        connection = AsyncMock()
        connection.__aenter__.return_value = client
        with patch("gpu_subnet.chain.make_guarded_client", return_value=connection):
            return await _run_command(None, args, None)

    async def test_exact_finalized_direct_weight_row_is_verified(self):
        client = MockChain()
        client.put_extrinsic(205, [event("WeightsSet", [NETUID, 0])])
        result = await reconcile_submission(client, entry({"extrinsic_id": "205-0007"}))
        self.assertEqual(client.find_calls, [205])
        self.assertEqual(result["status"], "weights_applied")
        self.assertEqual(result["extrinsic_id"], "205-0002")
        self.assertEqual(result["observed_weights"], {1: 43_690, 2: 65_535})

    async def test_exact_transaction_must_be_seen_even_if_receipt_has_a_block(self):
        client = MockChain()
        result = await reconcile_submission(client, entry({
            "block_hash": block_hash(204), "extrinsic_id": "204-0000", "success": True,
        }))
        self.assertEqual(result["status"], "awaiting_finality")
        self.assertCountEqual(client.find_calls, range(201, 207))

    async def test_retryable_expiration_requires_scanning_entire_bound(self):
        client = MockChain(finalized=223)
        result = await reconcile_submission(client, entry())
        self.assertEqual(result["status"], "expired_unseen")
        self.assertEqual(client.find_calls, list(range(201, 213)))

    async def test_expiration_conflicting_with_successful_receipt_is_unconfirmed(self):
        client = MockChain(finalized=223)
        result = await reconcile_submission(client, entry({
            "status": "commit_queued", "success": True,
            "block_hash": block_hash(205), "extrinsic_id": "205-0001",
        }))
        self.assertEqual(result["status"], "inclusion_unconfirmed")
        self.assertTrue(result["inclusion_conflict"])
        self.assertTrue(result["dispatch_success"])
        self.assertCountEqual(client.find_calls, range(201, 213))

    async def test_saved_receipt_conflicts_with_a_raw_match_in_a_different_block(self):
        client = MockChain()
        client.put_extrinsic(205, [event("WeightsSet", [NETUID, 0])])
        client.event_decode_error = ValueError("malformed events")
        receipt = {
            "status": "weights_submitted", "success": True,
            "block_hash": block_hash(204), "extrinsic_id": "204-0000",
        }
        checkpoints = []
        result = await reconcile_submission(client, entry(receipt), save_inclusion=checkpoints.append)
        self.assertEqual(checkpoints, [])
        self.assertTrue(result["inclusion_conflict"])
        self.assertTrue(result["dispatch_success"])
        self.assertEqual(result["inclusion_block_hash"], block_hash(204))
        self.assertEqual(result["observed_inclusion_block_hash"], block_hash(205))

    async def test_saved_receipt_conflicts_with_dispatch_failure_at_its_block(self):
        path = Path(self.enterContext(TemporaryDirectory())) / "submissions.sqlite3"
        journal = SubmissionJournal(path)
        journal.record_attempt(entry()["attempt"])
        journal.save_receipt(TX_HASH, {
            "status": "weights_submitted", "success": True,
            "block_hash": block_hash(205), "extrinsic_id": "205-0002",
        })
        client = MockChain()
        client.put_extrinsic(205, [event("ExtrinsicFailed", module="System")], success=False)

        result = await self._run_reconcile(path, client)
        self.assertEqual(result["status"], "inclusion_unconfirmed")
        self.assertTrue(result["inclusion_conflict"])
        self.assertTrue(result["dispatch_success"])
        self.assertFalse(result["conflicting_readback"]["observed_dispatch_success"])

    async def test_previous_conflicting_readback_keeps_successful_receipt_anchor(self):
        path = Path(self.enterContext(TemporaryDirectory())) / "submissions.sqlite3"
        journal = SubmissionJournal(path)
        journal.record_attempt(entry()["attempt"])
        journal.save_receipt(TX_HASH, {
            "status": "weights_submitted", "success": True,
            "block_hash": block_hash(205), "extrinsic_id": "205-0002",
        })
        journal.save_readback(TX_HASH, {
            "status": "dispatch_failed", "dispatch_success": False,
            "inclusion_block": 204, "inclusion_block_hash": block_hash(204),
            "finalized_block": 220, "extrinsic_id": "204-0000",
        })
        client = MockChain(finalized=220)
        client.put_extrinsic(205, [event("WeightsSet", [NETUID, 0])])

        result = await self._run_reconcile(path, client)
        self.assertTrue(result["inclusion_conflict"])
        self.assertEqual(result["inclusion_block_hash"], block_hash(205))
        self.assertEqual(result["observed_inclusion_block_hash"], block_hash(204))
        self.assertTrue(result["dispatch_success"])
        self.assertEqual((await self._run_reconcile(path, client))["status"], "weights_applied")

    async def test_unknown_receipt_without_a_block_can_expire(self):
        client = MockChain(finalized=223)
        result = await reconcile_submission(client, entry({
            "status": "submission_unconfirmed", "success": True,
        }))
        self.assertEqual(result["status"], "expired_unseen")

    async def test_lost_receipt_with_verified_inclusion_cannot_become_expired(self):
        previous = await reconcile_submission(self.commitment_chain(), entry())
        self.assertEqual(previous["status"], "commit_pending")

        client = MockChain(finalized=223)
        result = await reconcile_submission(client, entry(readback=previous))
        self.assertEqual(result["status"], "inclusion_unconfirmed")
        self.assertTrue(result["inclusion_conflict"])
        self.assertEqual(result["inclusion_block"], 205)
        self.assertEqual(result["inclusion_block_hash"], block_hash(205))
        self.assertEqual(client.find_calls[0], 205)
        self.assertCountEqual(client.find_calls, range(201, 213))
        self.assertTrue((await reconcile_submission(client, entry(readback=result)))["inclusion_conflict"])

    async def test_missing_commitment_transaction_keeps_window_reserved_after_reopen(self):
        path = Path(self.enterContext(TemporaryDirectory())) / "submissions.sqlite3"
        journal = SubmissionJournal(path)
        attempt = entry()["attempt"]
        journal.record_attempt(attempt)
        confirmed = await reconcile_submission(self.commitment_chain(), journal.get(TX_HASH))
        self.assertEqual(confirmed["status"], "commit_pending")
        journal.save_readback(TX_HASH, confirmed)

        missing = await reconcile_submission(MockChain(finalized=223), journal.get(TX_HASH))
        journal.save_readback(TX_HASH, missing)

        reopened = SubmissionJournal(path)
        saved = reopened.get(TX_HASH)["readback"]
        self.assertEqual(saved["status"], "inclusion_unconfirmed")
        self.assertTrue(saved["inclusion_conflict"])
        self.assertEqual(saved["inclusion_block_hash"], block_hash(205))
        self.assertTrue(saved["dispatch_success"])
        with self.assertRaisesRegex(JournalError, "already reserved"):
            reopened.record_attempt(attempt | {"extrinsic_hash": "0x" + "ab" * 32, "nonce": 2})

    async def test_reconcile_saves_inclusion_before_failing_historical_roster_read(self):
        path = Path(self.enterContext(TemporaryDirectory())) / "submissions.sqlite3"
        journal = SubmissionJournal(path)
        attempt = entry()["attempt"]
        journal.record_attempt(attempt)
        client = MockChain()
        client.put_extrinsic(205, [event("WeightsSet", [NETUID, 0])])

        async def missing_roster(*args, **kwargs):
            reopened = SubmissionJournal(path)
            self.assertIsNone(reopened.get(TX_HASH)["receipt"])
            self.assertEqual(reopened.get(TX_HASH)["readback"], {
                "status": "inclusion_verified",
                "extrinsic_hash": TX_HASH,
                "extrinsic_id": "205-0002",
                "finalized_block": 206,
                "inclusion_block": 205,
                "inclusion_block_hash": block_hash(205),
                "dispatch_success": True,
            })
            self.assertEqual(reopened.list_attempts()[0]["readback_status"], "inclusion_verified")
            raise OSError("historical roster unavailable")

        client.runtime_call = missing_roster
        with self.assertRaisesRegex(OSError, "historical roster unavailable"):
            await self._run_reconcile(path, client)

        saved = await self._run_reconcile(path, MockChain(finalized=223))
        self.assertTrue(saved["inclusion_conflict"])
        self.assertEqual(saved["inclusion_block_hash"], block_hash(205))
        with self.assertRaisesRegex(JournalError, "already reserved"):
            journal.record_attempt(attempt | {"extrinsic_hash": "0x" + "ab" * 32, "nonce": 2})

    async def test_reconcile_saves_raw_match_before_decoding_and_blocks_later_retry(self):
        path = Path(self.enterContext(TemporaryDirectory())) / "submissions.sqlite3"
        journal = SubmissionJournal(path)
        attempt = entry()["attempt"]
        journal.record_attempt(attempt)
        client = MockChain()
        client.put_extrinsic(205, [event("WeightsSet", [NETUID, 0])])
        client.event_decode_error = ValueError("malformed events")

        with self.assertRaisesRegex(ValueError, "malformed events"):
            await self._run_reconcile(path, client)

        reopened = SubmissionJournal(path)
        self.assertEqual(reopened.get(TX_HASH)["readback"], {
            "status": "inclusion_verified", "extrinsic_hash": TX_HASH,
            "extrinsic_id": "205-0002", "finalized_block": 206,
            "inclusion_block": 205, "inclusion_block_hash": block_hash(205),
        })
        result = await self._run_reconcile(path, MockChain(finalized=223))
        self.assertTrue(result["inclusion_conflict"])
        self.assertEqual(result["inclusion_block_hash"], block_hash(205))
        with self.assertRaisesRegex(JournalError, "already reserved"):
            reopened.record_attempt(attempt | {"extrinsic_hash": "0x" + "ab" * 32, "nonce": 2})

    async def test_inclusion_checkpoint_survives_cancellation_and_preserves_queue_result(self):
        path = Path(self.enterContext(TemporaryDirectory())) / "submissions.sqlite3"
        journal = SubmissionJournal(path)
        journal.record_attempt(entry()["attempt"])
        interrupted = self.commitment_chain()
        interrupted.query_map = AsyncMock(side_effect=asyncio.CancelledError)
        with self.assertRaises(asyncio.CancelledError):
            await self._run_reconcile(path, interrupted)
        self.assertEqual(journal.get(TX_HASH)["readback"]["status"], "inclusion_verified")

        confirmed = await self._run_reconcile(path, self.commitment_chain())
        self.assertEqual(confirmed["status"], "commit_pending")
        interrupted.finalized = 223
        with self.assertRaises(asyncio.CancelledError):
            await self._run_reconcile(path, interrupted)
        self.assertEqual(journal.get(TX_HASH)["readback"], confirmed)

        interrupted.extrinsics[205].events = [event("ExtrinsicSuccess", module="System")]
        self.assertEqual(await self._run_reconcile(path, interrupted), confirmed)

    async def test_previous_inclusion_takes_priority_over_receipt_hint(self):
        client = self.commitment_chain()
        previous = await reconcile_submission(client, entry())
        client.find_calls.clear()
        result = await reconcile_submission(client, entry({"extrinsic_id": "204-0000"}, previous))
        self.assertEqual(client.find_calls, [205])
        self.assertEqual(result["status"], "commit_pending")

    async def test_node_becomes_stale_relative_to_saved_inclusion(self):
        previous = await reconcile_submission(self.commitment_chain(), entry())
        client = MockChain(finalized=204)
        result = await reconcile_submission(client, entry(readback=previous))
        self.assertEqual(result["status"], "awaiting_finality")
        self.assertEqual(client.find_calls, [])

    async def test_exact_hash_at_a_different_finalized_block_conflicts(self):
        previous = await reconcile_submission(self.commitment_chain(), entry())
        client = MockChain(finalized=223)
        client.put_extrinsic(206, [event("WeightsSet", [NETUID, 0])])
        checkpoints = []
        result = await reconcile_submission(client, entry(readback=previous), save_inclusion=checkpoints.append)
        self.assertEqual(checkpoints, [])
        self.assertEqual(result["status"], "inclusion_unconfirmed")
        self.assertTrue(result["inclusion_conflict"])
        self.assertEqual(result["inclusion_block"], 205)
        self.assertEqual(result["observed_inclusion_block"], 206)

    async def test_conflicting_dispatch_failure_cannot_make_known_commit_retryable(self):
        previous = await reconcile_submission(self.commitment_chain(), entry())
        client = MockChain(finalized=223)
        client.put_extrinsic(205, [event("ExtrinsicFailed", module="System")], success=False)
        result = await reconcile_submission(client, entry(readback=previous))
        self.assertEqual(result["status"], "inclusion_unconfirmed")
        self.assertTrue(result["inclusion_conflict"])
        self.assertTrue(result["dispatch_success"])
        self.assertFalse(result["observed_dispatch_success"])

    async def test_consistent_dispatch_failure_remains_retryable(self):
        client = MockChain(finalized=223)
        client.put_extrinsic(205, [event("ExtrinsicFailed", module="System")], success=False)
        previous = await reconcile_submission(client, entry())
        result = await reconcile_submission(client, entry(readback=previous))
        self.assertEqual(result["status"], "dispatch_failed")
        self.assertFalse(result["dispatch_success"])

    async def test_unknown_dispatch_preserves_prior_definitive_outcome(self):
        previous = await reconcile_submission(self.commitment_chain(), entry())
        client = MockChain(finalized=223)
        client.put_extrinsic(205, [], success=False)
        result = await reconcile_submission(client, entry(readback=previous))
        self.assertEqual(result["status"], "inclusion_unconfirmed")
        self.assertTrue(result["dispatch_success"])
        self.assertNotIn("inclusion_conflict", result)

    async def test_partial_finality_leaves_attempt_pending(self):
        client = MockChain(finalized=200)
        result = await reconcile_submission(client, entry())
        self.assertEqual(result["status"], "awaiting_finality")
        self.assertEqual(client.find_calls, [])

    async def test_dispatch_failure_requires_an_explicit_failed_event(self):
        client = MockChain()
        client.put_extrinsic(205, [], success=False)
        self.assertEqual(
            (await reconcile_submission(client, entry()))["status"], "inclusion_unconfirmed"
        )
        client.put_extrinsic(205, [event("ExtrinsicFailed", module="System")], success=False)
        self.assertEqual((await reconcile_submission(client, entry()))["status"], "dispatch_failed")

    async def test_conflicting_system_events_cannot_verify_dispatch(self):
        client = MockChain()
        events = [
            event("WeightsSet", [NETUID, 0]),
            event("ExtrinsicFailed", module="System"),
            event("ExtrinsicSuccess", module="System"),
        ]
        for success in (True, False):
            with self.subTest(success=success):
                client.put_extrinsic(205, events, success=success)
                result = await reconcile_submission(client, entry())
                self.assertEqual(result["status"], "inclusion_unconfirmed")
                self.assertTrue(result["inclusion_conflict"])
                self.assertIsNone(result["dispatch_success"])

    async def test_direct_inclusion_detects_uid_reuse_and_row_mismatch(self):
        client = MockChain()
        client.put_extrinsic(205, [event("WeightsSet", [NETUID, 0])])
        client.hotkeys[1] = "replacement-miner"
        result = await reconcile_submission(client, entry())
        self.assertEqual(result["status"], "roster_mismatch")
        self.assertEqual(result["changed_uids"], [1])

        client.hotkeys[1] = "first-miner"
        client.stored_weights = [(1, 50_000), (2, 65_535)]
        result = await reconcile_submission(client, entry())
        self.assertEqual(result["status"], "weights_mismatch")

    async def test_wrong_chain_aborts_before_searching(self):
        client = MockChain()
        journal = entry()
        journal["attempt"]["genesis_hash"] = block_hash(99)
        with self.assertRaisesRegex(ChainError, "different chain"):
            await reconcile_submission(client, journal)
        self.assertEqual(client.find_calls, [])

    def commitment_chain(self, finalized=206):
        client = MockChain(finalized=finalized)
        client.put_extrinsic(205, [
            event("TimelockedWeightsCommitted", [HOTKEY, NETUID, COMMIT_HASH, 1234]),
        ])
        client.at_height[205] = [(10, [(HOTKEY, 205, "0x" + CIPHERTEXT.hex(), 1234)])]
        return client

    async def test_pending_queue_is_matched_by_exact_commitment(self):
        client = self.commitment_chain()
        result = await reconcile_submission(client, entry({"reveal_round": 99}))
        self.assertEqual(result["status"], "commit_pending")
        self.assertEqual(result["commit_hash"], COMMIT_HASH)
        self.assertEqual(result["reveal_round"], 1234)

        client.at_height[205] = [(10, [(HOTKEY, 205, "0x616263", 1234)])]
        result = await reconcile_submission(client, entry())
        self.assertEqual(result["status"], "reveal_unconfirmed")

    async def test_exact_queue_removal_event_and_weight_row_verify_the_reveal(self):
        client = self.commitment_chain(finalized=600)
        client.at_height[425] = []
        client.events_by_height[425] = [
            event("WeightsSet", [NETUID, 0]),
            event("TimelockedWeightsRevealed", [NETUID, HOTKEY]),
        ]
        result = await reconcile_submission(client, entry())
        self.assertEqual(result["status"], "reveal_applied")
        self.assertEqual(result["queue_disappearance_block"], 425)
        self.assertLess(len(client.queue_lookups), 15)

    async def test_overlapping_commitments_do_not_prove_which_was_revealed(self):
        client = self.commitment_chain(finalized=600)
        client.at_height[205][0][1].append((HOTKEY, 205, b"another.commit", 1234))
        client.at_height[425] = []
        client.events_by_height[425] = [
            event("WeightsSet", [NETUID, 0]),
            event("TimelockedWeightsRevealed", [NETUID, HOTKEY]),
        ]
        result = await reconcile_submission(client, entry())
        self.assertEqual(result["status"], "reveal_unconfirmed")

    async def test_queue_disappearance_alone_does_not_prove_application(self):
        client = self.commitment_chain(finalized=600)
        client.at_height[425] = []
        result = await reconcile_submission(client, entry())
        self.assertEqual(result["status"], "reveal_unconfirmed")
        self.assertNotIn("observed_weights", result)

    async def test_another_pending_commitment_does_not_hide_an_exact_reveal(self):
        client = self.commitment_chain(finalized=600)
        later = (11, [(HOTKEY, 300, b"later commit", 2345)])
        client.at_height[300] = [*client.at_height[205], later]
        client.at_height[425] = [later]
        client.at_height[500] = []
        client.events_by_height[425] = [
            event("WeightsSet", [NETUID, 0]),
            event("TimelockedWeightsRevealed", [NETUID, HOTKEY]),
        ]

        result = await reconcile_submission(client, entry())

        self.assertEqual(result["status"], "reveal_applied")
        self.assertEqual(result["queue_disappearance_block"], 425)
        self.assertIn(424, client.queue_lookups)
        self.assertIn(425, client.queue_lookups)

    async def test_same_block_commitments_must_be_accounted_for(self):
        client = self.commitment_chain(finalized=425)
        ciphertext = b"added during the reveal block"
        addition = (11, [(HOTKEY, 425, ciphertext, 2345)])
        commit_event = event("TimelockedWeightsCommitted", [
            HOTKEY, NETUID, "0x" + blake2b(ciphertext, digest_size=32).hexdigest(), 2345,
        ])
        reveal_events = [
            event("WeightsSet", [NETUID, 0]),
            event("TimelockedWeightsRevealed", [NETUID, HOTKEY]),
        ]
        cases = (
            ("addition confirmed to remain queued", [addition], [commit_event], "reveal_applied"),
            ("addition without event", [addition], [], "reveal_unconfirmed"),
            ("commit not visible after block", [], [commit_event], "reveal_unconfirmed"),
            ("multiple indistinguishable additions", [addition], [commit_event] * 2, "reveal_unconfirmed"),
        )
        for case, queue, commit_events, expected in cases:
            with self.subTest(case=case):
                client.at_height[425] = queue
                client.events_by_height[425] = reveal_events + commit_events
                result = await reconcile_submission(client, entry())
                self.assertEqual(result["status"], expected)

    async def test_duplicate_epoch_keys_or_commitment_identities_are_unconfirmed(self):
        client = self.commitment_chain(finalized=425)
        client.events_by_height[425] = [
            event("WeightsSet", [NETUID, 0]),
            event("TimelockedWeightsRevealed", [NETUID, HOTKEY]),
        ]
        later = (11, [(HOTKEY, 300, b"later commit", 2345)])
        test_cases = (
            ("duplicate epoch", [later, (11, [])]),
            ("duplicate identity", [later, (12, later[1])]),
        )
        for case, queue in test_cases:
            with self.subTest(case=case):
                client.at_height[425] = queue
                result = await reconcile_submission(client, entry())
                self.assertEqual(result["status"], "reveal_unconfirmed")
                self.assertNotIn("observed_weights", result)
