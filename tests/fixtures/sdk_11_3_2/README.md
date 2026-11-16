# Offline Bittensor decoding fixtures

`metadata-v15.scale.gz` contains the unmodified bytes of the V15 metadata RPC
response in `tests/fixtures/golden.json` from the Bittensor 11.3.2 source
distribution. The SDK recorded it on a local Subtensor node at spec version 461
and transaction version 1. Its block hash is
`0xd9f2d5c7e6b387e32b3f41d7808094cc966fbbbbd4709d96471c52d9b1a2b2aa` and its
uncompressed SHA-256 is
`3a61f5107a9404aa3871aa24eb063b23961567f1133ed8d02f06cd9bd82eefc2`.
[Bittensor 11.3.2 source distribution](https://pypi.org/project/bittensor/11.3.2/#files)

`replay.json` uses an inherent extrinsic from the same upstream fixture as
opaque bytes for the SDK's hash lookup. The blocks, events, weights, queue and
metagraph are synthetic SCALE vectors built against the recorded metadata. The
queue ciphertext includes non-UTF-8 bytes so the test covers the SDK's hex
representation. The SDK decodes these fixed inputs on every run.

The test replays chain reads using the SDK's real RPC read wrappers and native
SCALE decoder. The three scenarios cover a direct weight write, a pending
timelock commitment and its later reveal at spec version 461.
The direct write is also replayed with a pruned primary and a configured archive.

The upstream fixture data is distributed under the Apache License 2.0. See
`LICENSE-APACHE` in this directory.
