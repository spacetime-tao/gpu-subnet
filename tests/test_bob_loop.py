import unittest
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock, call

from gpu_subnet.bob_loop import run_bob_loop
from gpu_subnet.bob_scores import BobReport
from gpu_subnet.roster import ChainError


NETUID = 12
VALIDATOR = "validator"


def report(end_ts, digest="11"):
    return BobReport(NETUID, end_ts - 86_400, end_ts, (), digest * 32)


class BobLoopTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.timing = {}
        self.substrate = SimpleNamespace(
            block_hash=AsyncMock(side_effect=lambda block: f"0x{block:064x}"),
            query=AsyncMock(side_effect=self.query),
        )
        self.client = SimpleNamespace(
            finalized_block=AsyncMock(),
            block_time=AsyncMock(return_value=12.0),
            _substrate=self.substrate,
            execute=AsyncMock(),
        )
        self.fetch_report = AsyncMock()
        self.run_report = AsyncMock(return_value={"status": "preview_ready"})
        self.emit = Mock()
        self.sleep = AsyncMock()

    def query(self, module, item, params, *, block_hash):
        self.assertEqual(module, "SubtensorModule")
        self.assertEqual(params, [NETUID, VALIDATOR] if item == "Uids" else [NETUID])
        block = int(block_hash, 16)
        tempo, rate, updated = self.timing.get(block, (10, 0, 0))
        return {"Tempo": tempo, "WeightsSetRateLimit": rate, "Uids": 1, "LastUpdate": [3, updated]}[item]

    async def poll(self, heights, reports, *, max_polls=None):
        self.client.finalized_block.side_effect = heights
        self.fetch_report.side_effect = reports
        return await run_bob_loop(
            self.client, netuid=NETUID, fetch_report=self.fetch_report, run_report=self.run_report,
            emit=self.emit, validator_hotkey=VALIDATOR, max_polls=max_polls, sleep=self.sleep,
        )

    async def test_rereads_cadence_and_waits_for_actual_progress(self):
        self.timing = {
            100: (20, 10, 0),
            119: (20, 10, 0),
            120: (20, 30, 0),
            130: (20, 30, 0),
        }
        first, second = report(100_000), report(101_000)

        receipt = await self.poll([100, 119, 119, 120, 130], [first, second], max_polls=2)

        self.assertEqual(receipt, {"status": "preview_ready"})
        self.assertEqual(self.run_report.await_args_list, [call(first), call(second)])
        self.assertEqual(self.sleep.await_args_list, [call(12.0), call(12.0), call(60.0)])
        self.client.execute.assert_not_awaited()

    async def test_waits_after_previous_validator_update_on_startup(self):
        self.timing = {block: (20, 40, 95) for block in (100, 134, 135)}
        entry = report(100_000)

        await self.poll([100, 134, 135], [entry], max_polls=1)

        self.assertEqual(self.sleep.await_args_list, [call(60.0), call(12.0)])
        self.run_report.assert_awaited_once_with(entry)
        for block in self.timing:
            for item, params in (
                ("Tempo", [NETUID]), ("WeightsSetRateLimit", [NETUID]),
                ("Uids", [NETUID, VALIDATOR]), ("LastUpdate", [NETUID]),
            ):
                self.assertIn(
                    call("SubtensorModule", item, params, block_hash=f"0x{block:064x}"),
                    self.substrate.query.await_args_list,
                )

    async def test_later_chain_write_moves_polling_anchor(self):
        self.timing = {block: (10, 0, 103) for block in (110, 113)}
        first, second = report(100_000), report(101_000)
        self.run_report.side_effect = [{"status": "weights_submitted"}, {"status": "no_eligible_work"}]

        await self.poll([100, 110, 113], [first, second], max_polls=2)

        self.sleep.assert_awaited_once_with(36.0)
        self.assertEqual(self.run_report.await_args_list, [call(first), call(second)])

    async def test_only_handled_windows_are_skipped_on_repeated_timestamps(self):
        earlier, first, second = report(100_000), report(101_000), report(102_000)
        self.run_report.side_effect = [
            {"status": "future_report"},
            {"status": "weights_submitted"},
            {"status": "no_eligible_work"},
        ]

        await self.poll(
            [100, 110, 120, 130, 140], [first, first, earlier, report(first.end_ts, "22"), second],
            max_polls=5,
        )

        self.assertEqual(self.run_report.await_args_list, [call(first), call(first), call(second)])
        receipts = [emitted.args[0] for emitted in self.emit.call_args_list]
        self.assertEqual([receipt["status"] for receipt in receipts], [
            "future_report", "weights_submitted", "duplicate_window", "duplicate_window", "no_eligible_work",
        ])
        self.assertEqual(receipts[2]["reason"], "older_window")
        self.assertEqual(receipts[3]["reason"], "window_already_processed")
        self.assertEqual(receipts[3]["report_digest"], "22" * 32)

    async def test_corrected_report_can_be_handled_when_first_report_submitted_nothing(self):
        empty = report(100_000)
        corrected = report(empty.end_ts, "22")
        self.run_report.side_effect = [
            {"status": "no_eligible_work"}, {"status": "preview_ready"},
        ]

        await self.poll([100, 110], [empty, corrected], max_polls=2)

        self.assertEqual(self.run_report.await_args_list, [call(empty), call(corrected)])

    async def test_failure_and_unknown_submission_outcomes_stop_the_loop(self):
        for status in ("submission_failed", "submission_needs_review", "submission_unconfirmed"):
            with self.subTest(status=status):
                self.fetch_report.reset_mock()
                self.run_report.reset_mock()
                self.emit.reset_mock()
                failure = {"status": status}
                self.run_report.return_value = failure

                receipt = await self.poll([100], [report(100_000)])

                self.assertIs(receipt, failure)
                self.fetch_report.assert_awaited_once()
                self.run_report.assert_awaited_once()
                self.emit.assert_called_once_with(failure)

    async def test_fetch_exception_ends_loop_without_retry(self):
        error = OSError("scores endpoint unavailable")

        with self.assertRaisesRegex(OSError, "unavailable"):
            await self.poll([100], [error])

        self.fetch_report.assert_awaited_once()
        self.run_report.assert_not_awaited()
        self.emit.assert_not_called()

    async def test_malformed_cadence_does_not_fetch_scores(self):
        self.timing[100] = (0, 20, 0)

        with self.assertRaisesRegex(ChainError, "positive tempo"):
            await self.poll([100], [report(100_000)], max_polls=1)

        self.fetch_report.assert_not_awaited()

    async def test_finalized_height_regression_ends_loop(self):
        with self.assertRaisesRegex(ChainError, "moved backward"):
            await self.poll([100, 99], [report(100_000)], max_polls=2)

        self.fetch_report.assert_awaited_once()
