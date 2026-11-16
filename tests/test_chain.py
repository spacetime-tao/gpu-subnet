import asyncio
import contextlib
import io
import json
import sys
import tempfile
import unittest
from contextvars import ContextVar
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock, call, patch

from gpu_subnet.chain import _run_command, main, run_weights
from gpu_subnet.evidence import MinerWork, WorkReport
from gpu_subnet.journal import JournalError, SubmissionJournal
from gpu_subnet.roster import ChainError, Roster, read_roster
from gpu_subnet.submission import prepare_submission, submit_weights
from gpu_subnet.weights import ChainSnapshot, MinerSlot


NETUID = 7
GENESIS_HASH = "0x" + "11" * 32
ANCHOR_HASH = "0x" + "22" * 32
FINALIZED_HASH = "0x" + "33" * 32
HEAD_HASH = "0x" + "44" * 32


def metagraph(block=125):
    return {
        "netuid": NETUID,
        "block": block,
        "num_uids": 3,
        "hotkeys": ["validator", "miner-a", "miner-b"],
        "block_at_registration": [5, 19, 70],
        "validator_permit": [True, False, False],
        "active": [True, False, False],
    }


class RosterTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        hashes = {0: GENESIS_HASH, 120: ANCHOR_HASH, 125: FINALIZED_HASH, 129: HEAD_HASH}
        self.substrate = SimpleNamespace(
            block_hash=AsyncMock(side_effect=hashes.__getitem__),
            runtime_call=AsyncMock(return_value=metagraph()),
        )
        self.client = SimpleNamespace(
            finalized_block=AsyncMock(return_value=125),
            block=AsyncMock(return_value=129),
            _substrate=self.substrate,
        )

    async def test_default_roster_uses_finalized_block_and_keeps_headless_miners(self):
        roster = await read_roster(self.client, NETUID)
        self.client.finalized_block.assert_awaited_once_with()
        self.client.block.assert_not_awaited()
        self.assertEqual(roster.snapshot.genesis_hash, GENESIS_HASH)
        self.assertEqual(roster.snapshot.block, 125)
        self.assertEqual(roster.snapshot.block_hash, FINALIZED_HASH)
        self.assertEqual(roster.validator_hotkeys, frozenset({"validator"}))
        self.assertEqual(roster.snapshot.miners, (
            MinerSlot(0, "validator", 5),
            MinerSlot(1, "miner-a", 19),
            MinerSlot(2, "miner-b", 70),
        ))

    async def test_historical_roster_pins_query_to_requested_block_hash(self):
        self.substrate.runtime_call.return_value = metagraph(block=120)
        roster = await read_roster(self.client, NETUID, block=120)
        self.assertEqual(roster.snapshot.block_hash, ANCHOR_HASH)
        self.substrate.runtime_call.assert_awaited_once_with(
            "SubnetInfoRuntimeApi", "get_metagraph", [NETUID], block_hash=ANCHOR_HASH
        )

    async def test_inclusion_roster_reads_the_receipt_hash_directly(self):
        self.substrate.runtime_call.return_value = metagraph(block=129)
        roster = await read_roster(self.client, NETUID, block_hash=HEAD_HASH)
        self.assertEqual(roster.snapshot.block, 129)
        self.assertEqual(roster.snapshot.block_hash, HEAD_HASH)
        self.substrate.block_hash.assert_awaited_once_with(0)
        self.substrate.runtime_call.assert_awaited_once_with(
            "SubnetInfoRuntimeApi", "get_metagraph", [NETUID], block_hash=HEAD_HASH
        )

    async def test_unfinalized_anchor_is_rejected_before_metagraph_read(self):
        with self.assertRaises(ChainError):
            await read_roster(self.client, NETUID, block=129)
        self.substrate.runtime_call.assert_not_awaited()

    async def test_explicit_best_head_pins_to_head_hash(self):
        self.substrate.runtime_call.return_value = metagraph(block=129)
        roster = await read_roster(self.client, NETUID, finalized=False)
        self.client.block.assert_awaited_once_with()
        self.assertEqual(roster.snapshot.block_hash, HEAD_HASH)

    async def test_missing_subnet_and_incomplete_metagraph_fail_closed(self):
        for raw in (None, metagraph() | {"block_at_registration": [5, 19]}):
            with self.subTest(raw=raw):
                self.substrate.runtime_call.return_value = raw
                with self.assertRaises(ChainError):
                    await read_roster(self.client, NETUID)


class SubmissionTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.intent = SimpleNamespace(netuid=NETUID, weights=[70, 30], version_key=4)
        self.sdk = object()
        self.build_intent = self.enterContext(patch(
            "gpu_subnet.submission._encoded_intent", return_value=self.intent
        ))
        self.wallet = object()
        self.plan = SimpleNamespace(
            ok=True,
            violations=[],
            extras={},
            to_dict=lambda: {"ok": True, "warnings": [], "fee_tao": None},
        )
        self.client = SimpleNamespace(
            hyperparameters=SimpleNamespace(max_weight_limit=AsyncMock(return_value=65_535)),
            query=AsyncMock(return_value=4),
            plan=AsyncMock(return_value=self.plan),
            execute=AsyncMock(),
        )

    async def prepare(self, weights=None, version_key=4):
        if weights is None:
            weights = {12: 30, 7: 70}
        return await prepare_submission(
            self.sdk, self.client, self.wallet, netuid=NETUID, weights=weights,
            version_key=version_key,
        )

    async def test_preview_builds_set_weights_and_never_executes_it(self):
        intent, receipt = await self.prepare()
        self.assertIs(intent, self.intent)
        self.build_intent.assert_called_once_with(
            self.sdk, NETUID, {7: 65_535, 12: 28_087}, 4
        )
        self.client.plan.assert_awaited_once_with(self.intent, self.wallet, period=8, shielded=False)
        self.client.execute.assert_not_awaited()
        self.assertEqual(receipt["submission_path"], "direct_weights")
        self.assertEqual(receipt["encoded_weights"], {7: 65_535, 12: 28_087})

    async def test_preview_surfaces_timelock_reveal_round(self):
        self.plan.extras["reveal_round"] = 345
        _, receipt = await self.prepare()
        self.assertEqual(receipt["submission_path"], "timelocked_commit")
        self.assertEqual(receipt["reveal_round"], 345)
        self.client.execute.assert_not_awaited()

    async def test_infeasible_weights_do_not_get_padded_or_sent(self):
        self.client.hyperparameters.max_weight_limit.return_value = 19_660
        for weights in ({}, {7: 0}, {7: 70, 12: 30}):
            with self.subTest(weights=weights):
                with self.assertRaises(ChainError):
                    await self.prepare(weights=weights)
        self.build_intent.assert_not_called()
        self.client.plan.assert_not_awaited()
        self.client.execute.assert_not_awaited()

    async def test_validator_cannot_silently_use_a_newer_version_key(self):
        with self.assertRaises(ChainError):
            await self.prepare(version_key=3)
        self.client.plan.assert_not_awaited()
        self.client.execute.assert_not_awaited()

    async def test_only_successful_finalized_commit_reports_queued_weights(self):
        result = SimpleNamespace(
            success=True,
            data={"reveal_round": 345},
            block_hash=HEAD_HASH,
            extrinsic_id="130-0002",
            to_dict=lambda: {"success": True, "extrinsic_id": "130-0002"},
        )
        self.client._substrate = SimpleNamespace(_before_weight_broadcast=ContextVar("broadcast"))
        verify = AsyncMock()
        extrinsic = object()

        async def watch(*args, **kwargs):
            await self.client._substrate._before_weight_broadcast.get()(extrinsic, "validator")
            return result

        self.client.execute.side_effect = watch
        receipt = await submit_weights(
            self.client, self.wallet, self.intent, before_broadcast=verify,
        )
        verify.assert_awaited_once_with(extrinsic, "validator")
        self.client.execute.assert_awaited_once_with(
            self.intent, self.wallet, wait_for_inclusion=True,
            wait_for_finalization=True, period=8, shielded=False, retries=0,
        )
        self.assertEqual(receipt["status"], "commit_queued")
        self.assertEqual(receipt["extrinsic_id"], "130-0002")
        self.assertEqual(receipt["reveal_round"], 345)

    async def test_submission_rechecks_version_before_execution(self):
        intent, _ = await self.prepare()
        self.client.query.return_value = 5
        with self.assertRaises(ChainError):
            await submit_weights(self.client, self.wallet, intent, before_broadcast=AsyncMock())
        self.client.execute.assert_not_awaited()


class ChainWeightsTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.historical = Roster(ChainSnapshot(GENESIS_HASH, NETUID, 120, ANCHOR_HASH, (
            MinerSlot(0, "validator", 5),
            MinerSlot(1, "miner-a", 19),
            MinerSlot(2, "miner-b", 70),
        )), frozenset({"validator"}))
        self.latest = Roster(ChainSnapshot(GENESIS_HASH, NETUID, 129, HEAD_HASH, (
            MinerSlot(0, "validator", 5),
            MinerSlot(1, "replacement", 125),
            MinerSlot(6, "miner-a", 125),
            MinerSlot(8, "miner-b", 70),
        )), frozenset({"validator"}))
        self.report = WorkReport(GENESIS_HASH, NETUID, 100, 120, ANCHOR_HASH, (
            MinerWork("validator", 5, 10_000),
            MinerWork("miner-a", 19, 70),
            MinerWork("miner-b", 70, 30),
        ), "a1" * 32)
        self.sdk = SimpleNamespace(
            BittensorError=RuntimeError,
            public_view=Mock(return_value=SimpleNamespace(ss58_address="validator")),
        )
        self.client = SimpleNamespace(finalized_block=AsyncMock(return_value=125))
        self.wallet = object()
        self.intent = SimpleNamespace(mechid=0)
        self.plan = {
            "submission_path": "direct_weights", "signer_address": "validator",
            "encoded_weights": {8: 65_535}, "transaction_period_blocks": 8,
        }
        self.tx_hash = "0x" + "ab" * 32
        self.extrinsic = SimpleNamespace(extrinsic_hash=self.tx_hash, nonce=12)
        state_dir = Path(self.enterContext(tempfile.TemporaryDirectory()))
        self.journal_path = state_dir / "attempts.sqlite3"
        self.journal = SubmissionJournal(self.journal_path)
        self.read = self.enterContext(patch("gpu_subnet.chain.read_roster"))
        self.inclusion_hash = "0x" + "55" * 32
        self.included = replace(self.latest, snapshot=replace(
            self.latest.snapshot, block=130, block_hash=self.inclusion_hash
        ))
        self.read.side_effect = [self.historical, self.latest, self.latest, self.included]
        self.prepare = self.enterContext(patch("gpu_subnet.chain.prepare_submission"))
        self.prepare.return_value = (self.intent, self.plan)
        self.submit = self.enterContext(patch("gpu_subnet.chain.submit_weights"))
        self.submit.side_effect = self.guarded_send
        self.broadcast = Mock(return_value={
            "status": "weights_submitted", "success": True, "block_hash": self.inclusion_hash,
        })

    async def guarded_send(self, client, wallet, intent, *, before_broadcast):
        await before_broadcast(self.extrinsic, "validator")
        return self.broadcast()

    async def run_weights(self, report=None, **kwargs):
        return await run_weights(
            self.sdk, self.client, self.wallet, report or self.report, netuid=NETUID,
            window_blocks=20, **({"max_report_age_blocks": 20, "journal": self.journal} | kwargs),
        )

    async def test_preview_remaps_moving_uid_and_rejects_replacements(self):
        receipt = await self.run_weights()
        self.read.assert_has_awaits([
            call(self.client, NETUID, block=120),
            call(self.client, NETUID, finalized=False),
        ])
        self.assertEqual(receipt["status"], "preview_ready")
        self.assertEqual(receipt["weights"], {8: 30})
        self.assertEqual(self.prepare.call_args.kwargs["weights"], {8: 30})
        self.submit.assert_not_awaited()

    async def test_submission_is_explicit_and_checks_head_again(self):
        def broadcast():
            entry = SubmissionJournal(self.journal_path).get(self.tx_hash)
            self.assertIsNone(entry["receipt"])
            self.assertEqual(entry["attempt"]["encoded_weights"], {"8": 65_535})
            self.assertEqual(entry["attempt"]["scan_start_block"], 126)
            self.assertEqual(entry["attempt"]["nonce"], 12)
            return {"status": "weights_submitted", "success": True, "block_hash": self.inclusion_hash}

        self.broadcast.side_effect = broadcast
        receipt = await self.run_weights(submit=True)
        self.submit.assert_awaited_once()
        self.assertEqual(self.submit.await_args.args, (self.client, self.wallet, self.intent))
        self.broadcast.assert_called_once_with()
        self.assertEqual(receipt["status"], "weights_submitted")
        self.assertEqual(receipt["extrinsic_hash"], self.tx_hash)
        self.assertEqual(self.journal.get(self.tx_hash)["receipt"]["block_hash"], self.inclusion_hash)
        self.assertEqual(receipt["inclusion_roster"]["status"], "matched")
        self.assertEqual(self.read.await_args_list[-2:], [
            call(self.client, NETUID, finalized=False),
            call(self.client, NETUID, block_hash=self.inclusion_hash),
        ])

    async def test_old_report_never_produces_an_extrinsic(self):
        with self.assertRaises(ChainError):
            await self.run_weights(max_report_age_blocks=8, submit=True)
        self.prepare.assert_not_awaited()
        self.submit.assert_not_awaited()

    async def test_no_validator_permit_never_produces_an_extrinsic(self):
        self.read.side_effect = [self.historical, Roster(self.latest.snapshot, frozenset())]
        with self.assertRaises(ChainError):
            await self.run_weights(submit=True)
        self.prepare.assert_not_awaited()
        self.submit.assert_not_awaited()

    async def test_changed_weight_destination_after_plan_prevents_submission(self):
        new_slots = self.latest.snapshot.miners[:-1] + (MinerSlot(8, "new-owner", 130),)
        new_snapshot = replace(self.latest.snapshot, miners=new_slots, block=130)
        self.read.side_effect = [
            self.historical, self.latest, Roster(new_snapshot, self.latest.validator_hotkeys),
        ]
        with self.assertRaises(ChainError):
            await self.run_weights(submit=True)
        self.prepare.assert_awaited_once()
        self.broadcast.assert_not_called()

    async def test_inclusion_uid_change_is_reported_with_original_commit_receipt(self):
        new_slots = self.included.snapshot.miners[:-1] + (MinerSlot(8, "new-owner", 130),)
        changed = replace(self.included, snapshot=replace(self.included.snapshot, miners=new_slots))
        self.read.side_effect = [self.historical, self.latest, self.latest, changed]
        self.broadcast.return_value = {
            "status": "commit_queued", "success": True, "block_hash": self.inclusion_hash,
            "reveal_round": 321,
        }
        receipt = await self.run_weights(submit=True)
        self.assertEqual(receipt["status"], "submission_needs_review")
        self.assertEqual(receipt["submission"]["reveal_round"], 321)
        self.assertEqual(receipt["inclusion_roster"]["changed_uids"], [8])
        self.assertEqual(self.journal.get(self.tx_hash)["receipt"]["status"], "submission_needs_review")
        self.broadcast.assert_called_once_with()

    async def test_unavailable_inclusion_check_preserves_submission_receipt(self):
        self.read.side_effect = [self.historical, self.latest, self.latest, OSError("pruned")]
        receipt = await self.run_weights(submit=True)
        self.assertEqual(receipt["status"], "submission_needs_review")
        self.assertEqual(receipt["submission"]["block_hash"], self.inclusion_hash)
        self.assertEqual(receipt["inclusion_roster"]["status"], "unavailable")
        self.broadcast.assert_called_once_with()

    async def test_lost_connection_after_broadcast_leaves_attempt_for_recovery(self):
        self.broadcast.side_effect = OSError("lost RPC response")
        with self.assertRaises(OSError):
            await self.run_weights(submit=True)
        entry = SubmissionJournal(self.journal_path).get(self.tx_hash)
        self.assertIsNone(entry["receipt"])
        self.assertEqual(entry["attempt"]["broadcast_head_block"], 129)

        newer = replace(self.report, start_block=101, end_block=121)
        anchor = replace(self.historical, snapshot=replace(self.historical.snapshot, block=121))
        self.read.side_effect = [anchor, self.latest]
        self.extrinsic = SimpleNamespace(extrinsic_hash="0x" + "cd" * 32, nonce=11)
        with self.assertRaisesRegex(JournalError, f"reconcile unresolved submission {self.tx_hash}"):
            await self.run_weights(report=newer, submit=True, journal=SubmissionJournal(self.journal_path))
        self.submit.assert_awaited_once()

    async def test_stalled_watch_joins_cancellation_cleanup_and_saves_unknown_receipt(self):
        self.intent.netuid = NETUID
        self.intent.version_key = 0
        self.client.query = AsyncMock(return_value=0)
        self.client._substrate = SimpleNamespace(_before_weight_broadcast=ContextVar("broadcast"))
        cleanup_started, execution_stopped = asyncio.Event(), asyncio.Event()

        async def stalled_execution(*args, **kwargs):
            await self.client._substrate._before_weight_broadcast.get()(self.extrinsic, "validator")
            try:
                await asyncio.Event().wait()
            finally:
                cleanup_started.set()
                try:
                    await asyncio.Event().wait()
                finally:
                    execution_stopped.set()

        self.client.execute = AsyncMock(side_effect=stalled_execution)
        self.submit.side_effect = submit_weights
        with (
            patch("gpu_subnet.submission._FINALIZATION_WATCH_SECONDS", 0),
            patch("gpu_subnet.submission._WATCH_CLEANUP_SECONDS", 0),
        ):
            result = await asyncio.wait_for(self.run_weights(submit=True), timeout=2)

        self.assertTrue(cleanup_started.is_set())
        self.assertTrue(execution_stopped.is_set())
        self.assertEqual(result["status"], "submission_unconfirmed")
        self.assertEqual(result["extrinsic_hash"], self.tx_hash)
        reopened = SubmissionJournal(self.journal_path)
        self.assertEqual(reopened.get(self.tx_hash)["receipt"]["status"], "submission_unconfirmed")

    async def test_duplicate_window_fails_before_second_broadcast(self):
        self.broadcast.side_effect = OSError("lost RPC response")
        with self.assertRaises(OSError):
            await self.run_weights(submit=True)
        self.read.side_effect = [self.historical, self.latest, self.latest]
        self.extrinsic = SimpleNamespace(extrinsic_hash="0x" + "cd" * 32, nonce=13)
        with self.assertRaises(ValueError):
            await self.run_weights(submit=True)
        self.broadcast.assert_called_once_with()

    async def test_newer_in_flight_window_blocks_older_window_before_signing(self):
        newer = replace(self.report, start_block=101, end_block=121)

        async def read_roster(client, netuid, *, block=None, block_hash=None, finalized=True):
            if block is not None:
                return replace(self.historical, snapshot=replace(self.historical.snapshot, block=block))
            return self.included if block_hash is not None else self.latest

        signing, resume = asyncio.Event(), asyncio.Event()

        async def guarded_send(client, wallet, intent, *, before_broadcast):
            # Stall the newer window after signing but before journal reservation.
            self.assertFalse(signing.is_set(), "a second window reached signing")
            signing.set()
            await resume.wait()
            return await self.guarded_send(client, wallet, intent, before_broadcast=before_broadcast)

        self.read.side_effect = read_roster
        self.submit.side_effect = guarded_send
        newer_task = asyncio.create_task(self.run_weights(report=newer, submit=True))
        reopened = SubmissionJournal(self.journal_path)
        try:
            await asyncio.wait_for(signing.wait(), timeout=5)
            self.assertEqual(reopened.list_attempts(), [])
            with self.assertRaisesRegex(JournalError, "another weight submission is active"):
                await self.run_weights(submit=True, journal=reopened)
            self.submit.assert_awaited_once()
        finally:
            resume.set()
            await newer_task

        with self.assertRaisesRegex(JournalError, "before reserved window 121"):
            await self.run_weights(submit=True, journal=reopened)
        self.submit.assert_awaited_once()
        self.assertEqual(reopened.get(self.tx_hash)["attempt"]["end_block"], 121)

    async def test_signing_slot_is_released_on_cancellation_before_reservation(self):
        signing = asyncio.Event()

        async def paused_signing(client, wallet, intent, *, before_broadcast):
            signing.set()
            await asyncio.Event().wait()

        self.read.side_effect = [self.historical, self.latest]
        self.submit.side_effect = paused_signing
        task = asyncio.create_task(self.run_weights(submit=True))
        try:
            await asyncio.wait_for(signing.wait(), timeout=5)
        finally:
            task.cancel()
            with self.assertRaises(asyncio.CancelledError):
                await task

        self.read.side_effect = [self.historical, self.latest, self.latest, self.included]
        self.submit.side_effect = self.guarded_send
        result = await self.run_weights(submit=True, journal=SubmissionJournal(self.journal_path))
        self.assertEqual(result["status"], "weights_submitted")

    async def test_submission_without_journal_cannot_start(self):
        with self.assertRaisesRegex(ChainError, "journal"):
            await self.run_weights(submit=True, journal=None)
        self.read.assert_not_awaited()

    async def test_reconcile_command_records_readback_without_a_wallet(self):
        await self.run_weights(submit=True)
        args = SimpleNamespace(
            command="reconcile", journal=self.journal_path, tx_hash=self.tx_hash,
            netuid=NETUID, network="mock-network",
        )
        connection = AsyncMock()
        connection.__aenter__.return_value = self.client
        with (
            patch("gpu_subnet.chain.make_guarded_client", return_value=connection) as make_client,
            patch("gpu_subnet.chain.reconcile_submission", return_value={"status": "weights_applied"}) as read,
        ):
            receipt = await _run_command(self.sdk, args, None)
        make_client.assert_called_once_with(self.sdk, args.network, pin_finality=True)
        read.assert_awaited_once()
        self.assertEqual(read.await_args.args[1]["attempt"]["extrinsic_hash"], self.tx_hash)
        self.assertEqual(receipt, {"extrinsic_hash": self.tx_hash, "status": "weights_applied"})
        self.assertEqual(self.journal.get(self.tx_hash)["readback"], {"status": "weights_applied"})
        self.broadcast.assert_called_once_with()


class ChainCommandTests(unittest.TestCase):
    def test_reconcile_exit_codes_keep_readback_json(self):
        arguments = ["--network", "mock-network", "--netuid", "42", "reconcile", "--tx-hash", "mock-tx"]
        sdk = SimpleNamespace(__version__="11.3.2")
        outcomes = {
            "weights_applied": 0,
            "reveal_applied": 0,
            "awaiting_finality": 1,
            "inclusion_verified": 1,
            "commit_pending": 1,
            "dispatch_failed": 2,
            "expired_unseen": 2,
            "inclusion_unconfirmed": 2,
            "reveal_unconfirmed": 2,
            "roster_mismatch": 2,
            "weights_mismatch": 2,
            "unknown_status": 2,
        }
        for status, expected in outcomes.items():
            receipt = {"status": status, "extrinsic_hash": "mock-tx", "finalized_block": 125}
            with (
                self.subTest(status=status),
                patch.dict(sys.modules, {"bittensor": sdk}),
                patch("gpu_subnet.chain._run_command", return_value=receipt),
                contextlib.redirect_stdout(io.StringIO()) as output,
            ):
                self.assertEqual(main(arguments), expected)
                self.assertEqual(json.loads(output.getvalue()), receipt)

    def test_journal_history_does_not_call_the_chain(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "attempts.sqlite3"
            SubmissionJournal(path)
            with patch("gpu_subnet.chain._run_command") as run, contextlib.redirect_stdout(io.StringIO()) as output:
                result = main(["history", "--journal", str(path)])
        self.assertEqual(result, 0)
        self.assertEqual(json.loads(output.getvalue()), {"attempts": []})
        run.assert_not_called()

    def test_cli_requires_submit_flag_to_enable_write_path(self):
        example = Path(__file__).resolve().parent.parent / "examples"
        arguments = [
            "--network", "mock-network", "--netuid", "42", "weights",
            "--report", str(example / "report.json"),
            "--pool-public-key", str(example / "pool-public-key.hex"),
            "--window-blocks", "100", "--max-report-age-blocks", "5",
            "--wallet", "mock-wallet", "--hotkey", "mock-hotkey",
        ]
        sdk = SimpleNamespace(__version__="11.3.2")
        for flags, expect_submit in (([], False), (["--submit"], True)):
            with self.subTest(flags=flags):
                stdout = io.StringIO()
                with (
                    patch.dict(sys.modules, {"bittensor": sdk}),
                    patch("gpu_subnet.chain._run_command", return_value={"status": "stub"}) as run,
                    contextlib.redirect_stdout(stdout),
                ):
                    result = main(arguments + flags)
                self.assertEqual(result, 0)
                self.assertEqual(json.loads(stdout.getvalue()), {"status": "stub"})
                run.assert_awaited_once()
                self.assertIs(run.await_args.args[1].submit, expect_submit)

    def test_old_sdk_is_rejected_before_any_chain_command(self):
        sdk = SimpleNamespace(__version__="11.0.1")
        stderr = io.StringIO()
        with (
            patch.dict(sys.modules, {"bittensor": sdk}),
            patch("gpu_subnet.chain._run_command") as run,
            contextlib.redirect_stderr(stderr),
        ):
            result = main(["--network", "mock-network", "--netuid", "42", "roster"])
        self.assertEqual(result, 2)
        self.assertIn("Bittensor SDK 11.3.2 is required", stderr.getvalue())
        run.assert_not_called()
