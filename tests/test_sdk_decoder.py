import gzip
import json
import os
import socket
import unittest
from hashlib import blake2b
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

from gpu_subnet.journal import JournalError, SubmissionJournal
from gpu_subnet.readback import reconcile_submission
from gpu_subnet.roster import read_roster
from gpu_subnet.uid_guard import make_guarded_client


SDK_VERSION = "11.3.2"
FIXTURES = Path(__file__).parent / "fixtures" / "sdk_11_3_2"
NETUID = 27
MECHID = 1
INCLUSION = 205
REVEAL = 206
HOTKEYS = (
    "5CT5jwBEAhveEjgiSCQbkaKcKcUyF3VJ8qNXM9rXsuQyn3Kd",
    "5CqTdCcXCC7kv1Nwq2sCeJUNVqxbBPXjMAUXrbhRJtrUiyPP",
    "5DDqWU3pDgJsbH5BDsKoY2d8g5SD7jaAZVaYN3YJjtHygLwZ",
)
REGISTRATIONS = (12, 20, 42)
ENCODED_WEIGHTS = {1: 43690, 2: 65535}
COMMIT_HASH = "0x94c25a8934da73a6cade5daac4234f2c7a196f578c8c3d67dc0bc45cd4e5d315"


def block_hash(height):
    return f"0x{height:064x}"


class ReplayRpc:
    def __init__(self, vectors, metadata, scenario):
        self.responses = {}
        timelock = scenario != "direct"
        revealed = scenario == "reveal"
        included_at = block_hash(INCLUSION)
        finalized_at = block_hash(REVEAL) if revealed else included_at
        self.add("chain_getFinalizedHead", [], finalized_at)
        self.add("chain_getBlockHash", [0], block_hash(0))
        self.add("chain_getBlockHash", [INCLUSION], included_at)
        self.add("chain_getBlock", [included_at], {
            "block": {"header": {"number": hex(INCLUSION)}, "extrinsics": [vectors["extrinsic"]]},
        })
        parent = block_hash(INCLUSION - 1)
        self.add("chain_getHeader", [included_at], {
            "number": hex(INCLUSION), "parentHash": parent,
        })
        self.add("state_getRuntimeVersion", [parent], {
            "specVersion": 461, "transactionVersion": 1,
        })
        self.add("state_call", ["Metadata_metadata_at_version", "0x0f000000", parent], metadata)

        event_type = "commit" if timelock else "direct"
        self.add_storage(vectors["events"][event_type], included_at)
        if not timelock or revealed:
            self.add_storage(vectors["weights"], finalized_at)
            self.add(
                "state_call", ["SubnetInfoRuntimeApi_get_metagraph", "1b00", finalized_at],
                vectors["metagraph"][str(REVEAL if revealed else INCLUSION)],
            )
        if timelock:
            prefix = vectors["queue_prefix"]
            queue = vectors["queue"]
            self.add("state_getKeysPaged", [prefix, 100, prefix, included_at], [queue["key"]])
            self.add("state_queryStorageAt", [[queue["key"]], included_at], [
                {"block": included_at, "changes": [[queue["key"], queue["raw"]]]},
            ])
        if revealed:
            self.add("chain_getBlockHash", [REVEAL], finalized_at)
            self.add("chain_getHeader", [finalized_at], {
                "number": hex(REVEAL), "parentHash": included_at,
            })
            self.add("state_getRuntimeVersion", [included_at], {
                "specVersion": 461, "transactionVersion": 1,
            })
            self.add("state_getKeysPaged", [prefix, 100, prefix, finalized_at], [])
            self.add_storage(vectors["events"]["reveal"], finalized_at)
            self.add_storage(vectors["validator_uid"], finalized_at)

    def add(self, method, params, response):
        self.responses[method, json.dumps(params)] = response

    def add_storage(self, item, at):
        self.add("state_getStorageAt", [item["key"], at], item["raw"])

    async def request(self, method, params):
        key = (method, json.dumps(params))
        if key not in self.responses:
            raise AssertionError(f"unexpected RPC in offline replay: {method} {params}")
        return self.responses[key]


class SdkDecoderTests(unittest.IsolatedAsyncioTestCase):
    @classmethod
    def setUpClass(cls):
        try:
            installed_version = version("bittensor")
        except PackageNotFoundError:
            installed_version = None
        if installed_version != SDK_VERSION:
            message = f"offline decoder check requires the chain extra (bittensor=={SDK_VERSION})"
            if os.environ.get("GPU_SUBNET_REQUIRE_SDK_CHECK") == "1":
                raise RuntimeError(message)
            raise unittest.SkipTest(message)
        cls.vectors = json.loads((FIXTURES / "replay.json").read_text(encoding="utf-8"))
        cls.metadata = "0x" + gzip.decompress((FIXTURES / "metadata-v15.scale.gz").read_bytes()).hex()

    def setUp(self):
        cache = self.enterContext(TemporaryDirectory(prefix="gpu-subnet-sdk-test-"))
        self.enterContext(patch.dict(os.environ, {"BITTENSOR_RUNTIME_CACHE_DIR": cache}))
        for owner, name in (
            (socket.socket, "connect"), (socket.socket, "connect_ex"), (socket, "getaddrinfo"),
        ):
            self.enterContext(patch.object(
                owner, name, side_effect=AssertionError("network access in offline SDK check"),
            ))

    def client(self, scenario):
        import bittensor as sdk
        from bittensor._transport import SubstrateConnection

        endpoint = "ws://offline.invalid"
        client = make_guarded_client(sdk, endpoint)
        transport = SubstrateConnection(endpoint)
        rpc = ReplayRpc(self.vectors, self.metadata, scenario)
        self.enterContext(patch.object(transport._session, "request", side_effect=rpc.request))
        client._substrate._substrate = transport
        return client

    def install_archive(self, substrate, replay):
        from bittensor._transport import SubstrateConnection

        endpoint = "ws://archive.offline.invalid"
        archive = SubstrateConnection(endpoint)
        substrate.archive_endpoints = [endpoint]
        substrate._archive_substrate = archive
        return self.enterContext(patch.object(
            archive._session, "request", side_effect=replay.request,
        ))

    def submission(self):
        extrinsic_bytes = bytes.fromhex(self.vectors["extrinsic"][2:])
        return {
            "attempt": {
                "extrinsic_hash": "0x" + blake2b(extrinsic_bytes, digest_size=32).hexdigest(),
                "genesis_hash": block_hash(0),
                "netuid": NETUID,
                "mechid": MECHID,
                "validator_hotkey": HOTKEYS[0],
                "scan_start_block": INCLUSION,
                "broadcast_head_block": INCLUSION,
                "transaction_period_blocks": 8,
                "encoded_weights": ENCODED_WEIGHTS,
                "targets": [
                    {"uid": uid, "hotkey": HOTKEYS[uid], "registered_at": REGISTRATIONS[uid]}
                    for uid in ENCODED_WEIGHTS
                ],
            },
            "receipt": None,
        }

    async def test_decodes_extrinsic_events_stored_weights_and_roster(self):
        client = self.client("direct")
        result = await reconcile_submission(client, self.submission())
        self.assertEqual(result["status"], "weights_applied")
        self.assertEqual(result["inclusion_block"], INCLUSION)
        self.assertEqual(result["validator_uid"], 0)
        self.assertEqual(result["observed_weights"], ENCODED_WEIGHTS)
        roster = await read_roster(client, NETUID, block=INCLUSION)
        self.assertEqual(roster.validator_hotkeys, {HOTKEYS[0]})
        self.assertEqual(roster.snapshot.owner_hotkey, HOTKEYS[0])
        self.assertEqual(
            [(slot.uid, slot.hotkey, slot.registered_at) for slot in roster.snapshot.miners],
            list(zip(range(3), HOTKEYS, REGISTRATIONS)),
        )

    async def test_pruned_transaction_events_are_read_from_the_configured_archive(self):
        from bittensor._transport.errors import StateDiscardedError

        client = self.client("direct")
        substrate = client._substrate
        replay = ReplayRpc(self.vectors, self.metadata, "direct")
        event_query = [self.vectors["events"]["direct"]["key"], block_hash(INCLUSION)]

        async def primary_request(method, params):
            if method == "state_getStorageAt" and params == event_query:
                raise StateDiscardedError("primary pruned the inclusion events")
            return await replay.request(method, params)

        substrate.raw._session.request.side_effect = primary_request
        archive_request = self.install_archive(substrate, replay)
        result = await reconcile_submission(client, self.submission())
        self.assertEqual(result["status"], "weights_applied")
        self.assertEqual(result["inclusion_block_hash"], block_hash(INCLUSION))
        archive_request.assert_any_await("state_getStorageAt", event_query)
        self.assertNotIn("chain_getBlock", [call.args[0] for call in archive_request.await_args_list])

    async def test_missing_block_body_is_read_and_decoded_from_the_archive(self):
        substrate = self.client("direct")._substrate
        replay = ReplayRpc(self.vectors, self.metadata, "direct")
        archive_request = self.install_archive(substrate, replay)
        at = block_hash(INCLUSION)
        matches = []

        async def primary_request(method, params):
            self.assertEqual((method, params), ("chain_getBlock", [at]))
            return None

        substrate.raw._session.request.side_effect = primary_request
        result = await substrate.find_extrinsic(
            self.submission()["attempt"]["extrinsic_hash"], at,
            on_match=lambda number, index: matches.append((number, index)),
        )
        self.assertTrue(result.success)
        self.assertEqual(result.extrinsic_id, f"{INCLUSION}-0000")
        self.assertEqual(matches, [(INCLUSION, 0)])
        archive_request.assert_any_await("chain_getBlock", [at])

    async def test_unavailable_block_body_does_not_report_transaction_absence(self):
        import bittensor as sdk

        substrate = self.client("direct")._substrate
        substrate.raw._session.request.side_effect = None
        substrate.raw._session.request.return_value = None
        with self.assertRaises(sdk.BittensorError):
            await substrate.find_extrinsic(
                self.submission()["attempt"]["extrinsic_hash"], block_hash(INCLUSION),
            )

    async def test_raw_transaction_match_is_saved_before_event_decoding_failure(self):
        client = self.client("direct")
        substrate = client._substrate
        replay = ReplayRpc(self.vectors, self.metadata, "direct")
        at = block_hash(INCLUSION)
        event_query = [self.vectors["events"]["direct"]["key"], at]
        path = Path(self.enterContext(TemporaryDirectory())) / "submissions.sqlite3"
        journal = SubmissionJournal(path)
        attempt = self.submission()["attempt"] | {
            "start_block": INCLUSION - 2,
            "end_block": INCLUSION - 1,
            "end_block_hash": block_hash(INCLUSION - 1),
            "nonce": 2,
            "report_digest": "c" * 64,
        }
        tx_hash = attempt["extrinsic_hash"]
        journal.record_attempt(attempt)

        async def corrupted_events(method, params):
            if (method, params) == ("state_getStorageAt", event_query):
                saved = journal.get(tx_hash)["readback"]
                self.assertEqual(saved["status"], "inclusion_verified")
                self.assertEqual(saved["inclusion_block"], INCLUSION)
                self.assertEqual(saved["inclusion_block_hash"], at)
                self.assertEqual(saved["extrinsic_id"], f"{INCLUSION}-0000")
                self.assertIsNone(saved.get("dispatch_success"))
                return "0x04"  # Truncated SCALE vector declaring one event.
            return await replay.request(method, params)

        substrate.raw._session.request.side_effect = corrupted_events
        with self.assertRaises(ValueError):
            await reconcile_submission(
                client, journal.get(tx_hash),
                save_inclusion=lambda checkpoint: journal.save_readback(tx_hash, checkpoint),
            )
        reopened = SubmissionJournal(path)
        self.assertEqual(reopened.get(tx_hash)["readback"]["inclusion_block_hash"], at)
        with self.assertRaisesRegex(JournalError, "already reserved"):
            reopened.record_attempt(attempt | {"extrinsic_hash": "0x" + "d" * 64, "nonce": 3})

    async def test_decodes_commit_event_and_ciphertext_in_queue_page(self):
        result = await reconcile_submission(self.client("commit"), self.submission())
        self.assertEqual(result["status"], "commit_pending")
        self.assertEqual(result["commit_hash"], COMMIT_HASH)
        self.assertEqual(result["reveal_round"], 1234)

    async def test_decodes_reveal_events_and_validator_uid(self):
        result = await reconcile_submission(self.client("reveal"), self.submission())
        self.assertEqual(result["status"], "reveal_applied")
        self.assertEqual(result["queue_disappearance_block"], REVEAL)
        self.assertEqual(result["validator_uid"], 0)
        self.assertEqual(result["observed_weights"], ENCODED_WEIGHTS)
