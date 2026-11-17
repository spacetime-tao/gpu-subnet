import contextlib
import io
import json
import unittest
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock, patch

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from gpu_subnet.bob_scores import load_bob_report
from gpu_subnet.chain import main, preview_bob_chain
from gpu_subnet.roster import ChainError


NETUID = 12
END_TS = 1_731_786_400
START_TS = END_TS - 86_400
GENESIS_HASH = "0x" + "11" * 32
HEAD_HASH = "0x" + "22" * 32
OWNER = "5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY"
VALIDATOR = "5FHneW46xGXgs5mUiveU4sbTyGBzmstUspZC92UhjJM694ty"
MINER_A = "5CT5jwBEAhveEjgiSCQbkaKcKcUyF3VJ8qNXM9rXsuQyn3Kd"
MINER_B = "5CqTdCcXCC7kv1Nwq2sCeJUNVqxbBPXjMAUXrbhRJtrUiyPP"
UNREGISTERED = "5DDqWU3pDgJsbH5BDsKoY2d8g5SD7jaAZVaYN3YJjtHygLwZ"


class BobChainPreviewTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        # Test fixture only. No Bittensor signing key or live API is needed.
        self.pool_key = Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
        self.metagraph = {
            "netuid": NETUID,
            "block": 125,
            "num_uids": 4,
            "hotkeys": [OWNER, VALIDATOR, MINER_B, MINER_A],
            "block_at_registration": [5, 10, 20, 30],
            "validator_permit": [True, True, False, False],
            "owner_hotkey": OWNER,
        }
        self.substrate = SimpleNamespace(
            block_hash=AsyncMock(side_effect={0: GENESIS_HASH, 125: HEAD_HASH}.__getitem__),
            runtime_call=AsyncMock(return_value=self.metagraph),
        )
        self.intent = object()
        self.build_intent = self.enterContext(patch(
            "gpu_subnet.submission._encoded_intent", return_value=self.intent
        ))
        self.plan = SimpleNamespace(
            ok=True,
            extras={},
            to_dict=lambda: {"signer_address": VALIDATOR},
        )
        self.client = SimpleNamespace(
            _substrate=self.substrate,
            block=AsyncMock(return_value=125),
            finalized_block=AsyncMock(),
            hyperparameters=SimpleNamespace(max_weight_limit=AsyncMock(return_value=65_535)),
            query=AsyncMock(return_value=4),
            plan=AsyncMock(return_value=self.plan),
            execute=AsyncMock(),
        )
        self.sdk = SimpleNamespace(
            public_view=Mock(return_value=SimpleNamespace(ss58_address=VALIDATOR)),
        )
        self.wallet = object()

    def report(self, scores):
        rows = [
            {
                "hotkey": hotkey,
                "workers": 1,
                "verified_work": verified_work,
                "shares": 1,
                "invalid_rate": invalid_rate,
                "red": 0,
                "audited": 0,
                "chat": {"served": 0, "failed": 0, "ttft_p50_s": None, "tok_s_p50": None},
            }
            for hotkey, verified_work, invalid_rate in scores
        ]
        report = json.dumps({
            "version": 1,
            "netuid": NETUID,
            "window": {"start_ts": START_TS, "end_ts": END_TS},
            "scores": rows,
        })
        key_hex = self.pool_key.public_key().public_bytes_raw().hex()
        envelope = json.dumps({
            "report": report,
            "sig": self.pool_key.sign(report.encode("utf-8")).hex(),
            "pubkey": key_hex,
            "alg": "ed25519",
        }).encode("utf-8")
        return load_bob_report(envelope, key_hex, netuid=NETUID)

    async def preview(self, report, *, now=END_TS + 10):
        return await preview_bob_chain(
            self.sdk, self.client, self.wallet, report, netuid=NETUID,
            max_report_age_seconds=60, now=now, version_key=4,
        )

    async def test_preview_uses_current_roster_for_exact_unsigned_plan(self):
        report = self.report([
            (OWNER, 1000, 0.0),
            (VALIDATOR, 1000, 0.0),
            (UNREGISTERED, 1000, 0.0),
            (MINER_A, 100, 0.25),
            (MINER_B, 25, 0.0),
        ])

        receipt = await self.preview(report)

        self.assertEqual(receipt["status"], "preview_ready")
        self.assertEqual(receipt["netuid"], NETUID)
        self.assertEqual(receipt["validator_hotkey"], VALIDATOR)
        self.assertEqual((receipt["start_ts"], receipt["end_ts"]), (START_TS, END_TS))
        self.assertEqual(receipt["report_digest"], report.digest)
        self.assertEqual((receipt["roster_block"], receipt["roster_block_hash"]), (125, HEAD_HASH))
        self.assertEqual(receipt["normalized_weights"], {2: 0.25, 3: 0.75})
        self.assertEqual(receipt["plan"]["encoded_weights"], {2: 21_845, 3: 65_535})
        self.assertEqual(receipt["plan"]["submission_path"], "direct_weights")
        self.substrate.runtime_call.assert_awaited_once_with(
            "SubnetInfoRuntimeApi", "get_metagraph", [NETUID], block_hash=HEAD_HASH
        )
        self.build_intent.assert_called_once_with(self.sdk, NETUID, {2: 21_845, 3: 65_535}, 4)
        self.client.plan.assert_awaited_once()
        self.client.execute.assert_not_awaited()

    async def test_no_eligible_work_does_not_prepare_a_transaction(self):
        report = self.report([(OWNER, 1000, 0.0), (VALIDATOR, 100, 0.0), (MINER_A, 0, 0.0)])

        receipt = await self.preview(report)

        self.assertEqual(receipt["status"], "no_eligible_work")
        self.assertEqual(receipt["normalized_weights"], {})
        self.client.plan.assert_not_awaited()
        self.client.execute.assert_not_awaited()

    async def test_stale_or_future_report_does_not_prepare_a_transaction(self):
        report = self.report([(MINER_A, 100, 0.0)])
        for now in (END_TS - 1, END_TS + 61):
            with self.subTest(now=now), self.assertRaises(ChainError):
                await self.preview(report, now=now)
        self.client.plan.assert_not_awaited()
        self.client.execute.assert_not_awaited()

    async def test_selected_hotkey_requires_a_validator_permit(self):
        report = self.report([(MINER_A, 100, 0.0)])
        self.metagraph["validator_permit"][1] = False

        with self.assertRaisesRegex(ChainError, "permit"):
            await self.preview(report)

        self.client.plan.assert_not_awaited()
        self.client.execute.assert_not_awaited()

    async def test_owner_identity_is_required_before_preparing_weights(self):
        report = self.report([(OWNER, 100, 0.0)])
        del self.metagraph["owner_hotkey"]

        with self.assertRaisesRegex(ValueError, "owner hotkey"):
            await self.preview(report)

        self.client.plan.assert_not_awaited()
        self.client.execute.assert_not_awaited()

    async def test_plan_must_be_for_selected_hotkey(self):
        report = self.report([(MINER_A, 100, 0.0)])
        self.plan.to_dict = lambda: {"signer_address": OWNER}

        with self.assertRaisesRegex(ChainError, "signer"):
            await self.preview(report)

        self.client.execute.assert_not_awaited()


class BobChainCliTests(unittest.TestCase):
    def test_bob_weights_has_no_submit_option(self):
        stderr = io.StringIO()
        with contextlib.redirect_stderr(stderr), self.assertRaises(SystemExit) as raised:
            main([
                "--network", "local", "--netuid", str(NETUID), "bob-weights",
                "--report", "report.json", "--pool-public-key", "pool.hex",
                "--max-report-age-seconds", "60", "--wallet", "wallet", "--hotkey", "validator",
                "--submit",
            ])
        self.assertEqual(raised.exception.code, 2)
        self.assertIn("unrecognized arguments: --submit", stderr.getvalue())
