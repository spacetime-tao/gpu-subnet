"""Exercise the SDK transport hook with a local fake and no sockets."""

import asyncio
import unittest
from types import SimpleNamespace

from gpu_subnet.roster import ChainError
from gpu_subnet.uid_guard import guard_broadcast, make_guarded_client


class FakeRpcSubstrate:
    def __init__(self, endpoint, **options):
        self.endpoint = endpoint
        self.options = options
        self.events = []

    async def _submit_and_report(self, extrinsic, **options):
        self.events.append(("broadcast", extrinsic.nonce, options))
        return "mock receipt"

    def release_nonce_reservation(self, signer_address, first, count):
        self.events.append(("release", signer_address, first, count))


class BroadcastGuardTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.sdk = SimpleNamespace(
            RpcSubstrate=FakeRpcSubstrate,
            Client=lambda network, *, substrate: SimpleNamespace(_substrate=substrate),
            settings=SimpleNamespace(
                resolve_endpoint=lambda network: ("label", "primary"),
                default_fallback_endpoints=lambda label: ["primary", "fallback"],
                default_archive_endpoints=lambda label: ["archive"],
            ),
        )
        self.client = make_guarded_client(self.sdk, "unused")
        self.transport = self.client._substrate
        self.extrinsic = SimpleNamespace(nonce=24)
        self.options = {
            "signer_address": "validator",
            "wait_for_inclusion": True,
            "wait_for_finalization": True,
            "reservation": None,
            "reset_nonce_cache": True,
        }

    async def test_check_precedes_broadcast_and_clears_on_scope_exit(self):
        async def check(extrinsic, signer_address):
            self.assertIs(extrinsic, self.extrinsic)
            self.transport.events.append(("check", signer_address))

        with guard_broadcast(self.client, check):
            result = await self.transport._submit_and_report(self.extrinsic, **self.options)
        self.assertEqual(result, "mock receipt")
        await self.transport._submit_and_report(self.extrinsic, **self.options)
        self.assertEqual(
            self.transport.events,
            [("check", "validator"), ("broadcast", 24, self.options), ("broadcast", 24, self.options)],
        )
        self.assertEqual(self.transport.options, {
            "fallback_endpoints": ["fallback"], "archive_endpoints": ["archive"]
        })

    def test_send_can_pin_the_primary_endpoint(self):
        client = make_guarded_client(self.sdk, "unused", allow_failover=False)
        self.assertEqual(client._substrate.options, {
            "fallback_endpoints": [], "archive_endpoints": ["archive"]
        })

    async def test_rejected_check_releases_only_the_abandoned_nonce(self):
        failure = ChainError("UID changed after signing")

        async def check(extrinsic, signer_address):
            raise failure

        with self.assertRaises(ChainError) as caught, guard_broadcast(self.client, check):
            await self.transport._submit_and_report(self.extrinsic, **self.options)
        self.assertIs(caught.exception, failure)
        self.assertEqual(self.transport.events, [("release", "validator", 24, 1)])

    async def test_explicit_reservation_is_released_on_cancel(self):
        async def check(extrinsic, signer_address):
            raise asyncio.CancelledError

        options = self.options | {"reservation": (23, 2), "reset_nonce_cache": False}
        with self.assertRaises(asyncio.CancelledError), guard_broadcast(self.client, check):
            await self.transport._submit_and_report(self.extrinsic, **options)
        self.assertEqual(self.transport.events, [("release", "validator", 23, 2)])

    async def test_guard_scope_does_not_affect_concurrent_task(self):
        ready = asyncio.Event()

        async def unrelated():
            await ready.wait()
            return await self.transport._submit_and_report(self.extrinsic, **self.options)

        async def check(extrinsic, signer_address):
            raise ChainError("unexpected guard in other task")

        task = asyncio.create_task(unrelated())
        with guard_broadcast(self.client, check):
            ready.set()
            self.assertEqual(await task, "mock receipt")

    def test_unguarded_client_is_rejected(self):
        with self.assertRaises(ChainError), guard_broadcast(SimpleNamespace(), lambda *_: None):
            self.fail("accepted a client without a broadcast guard")
