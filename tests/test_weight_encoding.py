import sys
import unittest
from types import ModuleType, SimpleNamespace
from unittest.mock import AsyncMock, Mock, patch

from gpu_subnet.roster import ChainError
from gpu_subnet.submission import _encoded_intent
from gpu_subnet.weight_encoding import U16_MAX, encode_weights


class EncodeWeightsTests(unittest.TestCase):
    def test_skewed_scores_clip_to_exactly_sixty_percent(self):
        self.assertEqual(
            encode_weights({12: 1_000_000_000, 7: 1}, 39_321),
            {7: 43_690, 12: U16_MAX},
        )

    def test_cap_equality_requires_uniform_weights(self):
        self.assertEqual(
            encode_weights({3: 1, 1: 1_000_000_000, 5: 29}, U16_MAX // 3),
            {1: U16_MAX, 3: U16_MAX, 5: U16_MAX},
        )

    def test_positive_targets_preserve_rank_and_survive_quantization(self):
        encoded = encode_weights({12: 1 << 63, 7: 1, 9: 1 << 62}, U16_MAX)
        self.assertEqual(list(encoded), [7, 9, 12])
        self.assertEqual(encoded, {7: 1, 9: 32_768, 12: U16_MAX})

    def test_rounding_keeps_the_vector_within_the_cap(self):
        cap = 35_000
        encoded = encode_weights({2: 1, 3: 2, 5: (1 << 64) - 1}, cap)
        self.assertLessEqual(max(encoded.values()) * U16_MAX, cap * sum(encoded.values()))
        self.assertLessEqual(encoded[2], encoded[3])
        self.assertLess(encoded[3], encoded[5])

    def test_invalid_or_infeasible_vectors_are_rejected(self):
        cases = (
            ({}, U16_MAX),
            ({-1: 1}, U16_MAX),
            ({1: 0}, U16_MAX),
            ({1: 1 << 64}, U16_MAX),
            ({1: 1}, U16_MAX + 1),
            ({1: 1, 2: 2}, U16_MAX // 2),
        )
        for weights, cap in cases:
            with self.subTest(weights=weights, cap=cap), self.assertRaises(ChainError):
                encode_weights(weights, cap)


class FakeSetWeights:
    def __init__(self, *, netuid, weights, version_key):
        self.netuid = netuid
        self.mechid = 0
        self.version_key = version_key
        self.uids = sorted(weights)
        self.weights = [float(weights[uid]) for uid in self.uids]

    def hotkey_address(self, wallet):
        return wallet.ss58_address

    def hotkey_public_key(self, wallet):
        return wallet.public_key


def exact_conform(uids, weights, preflight, netuid, *, raw_u16):
    if not raw_u16:
        raise AssertionError("the SDK must receive the exact encoded weights")
    if max(weights) * U16_MAX > preflight.max_weight_limit * sum(weights):
        raise ChainError("encoded weights exceed the current cap")
    return list(uids), [int(weight) for weight in weights]


class EncodedIntentTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.preflight = SimpleNamespace(commit_reveal=False, max_weight_limit=39_321)
        self.sdk_weights = ModuleType("bittensor.intents.weights")
        self.sdk_weights.DEFAULT_COMMIT_REVEAL_VERSION = 4
        self.sdk_weights._preflight = AsyncMock(return_value=self.preflight)
        self.sdk_weights._conform = Mock(side_effect=exact_conform)
        self.sdk_weights._build_timelocked = AsyncMock(return_value="commit")
        self.enterContext(patch.dict(sys.modules, {self.sdk_weights.__name__: self.sdk_weights}))

        self.call = Mock(return_value="plaintext_call")
        self.sdk = SimpleNamespace(SetWeights=FakeSetWeights, calls=SimpleNamespace(
            SubtensorModule=SimpleNamespace(set_mechanism_weights=self.call)
        ))
        self.substrate = SimpleNamespace(compose=AsyncMock(return_value="composed"))
        self.wallet = SimpleNamespace(ss58_address="hotkey", public_key=b"test-key")
        self.intent = _encoded_intent(self.sdk, 27, {7: 43_690, 12: U16_MAX}, 9)

    async def test_plaintext_call_retains_exact_encoded_weights(self):
        self.assertEqual(await self.intent.build(self.substrate, self.wallet), "composed")
        self.sdk_weights._preflight.assert_awaited_once_with(self.substrate, "hotkey", 27, 0)
        self.sdk_weights._conform.assert_called_once_with(
            [7, 12], [43_690, U16_MAX], self.preflight, 27, raw_u16=True,
        )
        self.call.assert_called_once_with(
            netuid=27, mecid=0, dests=[7, 12], weights=[43_690, U16_MAX], version_key=9,
        )
        self.substrate.compose.assert_awaited_once_with("plaintext_call")
        self.sdk_weights._build_timelocked.assert_not_awaited()

    async def test_timelock_call_retains_exact_encoded_weights(self):
        self.preflight.commit_reveal = True
        self.assertEqual(await self.intent.build(self.substrate, self.wallet), "commit")
        self.sdk_weights._build_timelocked.assert_awaited_once_with(
            self.substrate, b"test-key", 27, 0, [7, 12], [43_690, U16_MAX], 9, 4,
        )
        self.substrate.compose.assert_not_awaited()

    async def test_lowered_cap_rejects_the_vector_without_reclipping(self):
        self.preflight.max_weight_limit = 36_000
        with self.assertRaisesRegex(ChainError, "current cap"):
            await self.intent.build(self.substrate, self.wallet)
        self.substrate.compose.assert_not_awaited()
        self.sdk_weights._build_timelocked.assert_not_awaited()
