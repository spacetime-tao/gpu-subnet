import socket
import unittest
from importlib.metadata import PackageNotFoundError, version
from unittest.mock import patch

from gpu_subnet.chain import _SDK_VERSION
from gpu_subnet.roster import ChainError
from gpu_subnet.uid_guard import make_guarded_client


def block_hash(height):
    return f"0x{height:064x}"


class FinalityViewTests(unittest.IsolatedAsyncioTestCase):
    @classmethod
    def setUpClass(cls):
        try:
            installed_version = version("bittensor")
        except PackageNotFoundError:
            installed_version = None
        if installed_version != _SDK_VERSION:
            raise unittest.SkipTest("requires the pinned chain extra")

    def setUp(self):
        for owner, name in (
            (socket.socket, "connect"), (socket.socket, "connect_ex"), (socket, "getaddrinfo"),
        ):
            self.enterContext(patch.object(
                owner, name, side_effect=AssertionError("network access in offline finality check"),
            ))

        import bittensor as sdk
        from bittensor._transport import SubstrateConnection

        endpoint = "ws://offline.invalid"
        self.client = make_guarded_client(sdk, endpoint, pin_finality=True)
        transport = SubstrateConnection(endpoint)
        self.substrate = self.client._substrate
        self.substrate._substrate = transport
        self.session = transport._session
        self.primary_socket = object()
        self.session._ws = self.primary_socket

    async def test_discards_block_hash_when_connection_switches_during_lookup(self):
        async def request(method, params):
            if method == "chain_getFinalizedHead":
                return block_hash(206 if self.session._ws is self.primary_socket else 204)
            if method == "chain_getHeader":
                return {"number": hex(int(params[0], 16))}
            if method == "chain_getBlockHash" and params == [205]:
                self.session._ws = object()
                return block_hash(900)
            raise AssertionError(f"unexpected RPC in offline finality check: {method} {params}")

        with patch.object(self.session, "request", side_effect=request) as calls:
            self.assertEqual(await self.client.finalized_block(), 206)
            with self.assertRaisesRegex(ChainError, "connection changed"):
                await self.substrate.block_hash(205)
            calls.assert_any_await("chain_getHeader", [block_hash(204)])
            count = calls.await_count
            with self.assertRaisesRegex(ChainError, "connection changed"):
                await self.substrate.block_hash(205)
            self.assertEqual(calls.await_count, count)

    async def test_height_queries_never_consult_archive_after_primary_error(self):
        import bittensor as sdk
        from bittensor._transport.errors import StateDiscardedError

        with (
            patch.object(self.session, "request", side_effect=StateDiscardedError("pruned height")),
            patch.object(self.substrate, "_archive") as archive,
        ):
            with self.assertRaises(sdk.BittensorError):
                await self.substrate.block_hash(205)
            archive.assert_not_awaited()
