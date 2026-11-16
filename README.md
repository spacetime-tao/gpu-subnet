# GPU subnet validator

The validator turns a signed pool report into relative work totals by Bittensor UID. It supports offline replay and an optional Bittensor connection for roster reads, transaction previews, and explicit weight submission. The scores command captures HTTP responses for later verification. The snapshot and report in `examples/` are synthetic.

## Run the example

From the project directory with Python 3.11 or newer and `uv` installed:

```sh
uv run gpu-subnet-validate \
  --report examples/report.json \
  --snapshot examples/snapshot.json \
  --pool-public-key examples/pool-public-key.hex \
  --window-blocks 100
```

The receipt gives UID `7` relative work `700` and UID `12` relative work `300`. A valid window with zero eligible work returns `no_eligible_work` and an empty map. A rejected report exits with status `2` and prints a diagnostic to stderr.

```sh
uv run python -m unittest discover -s tests -v
```

The offline SCALE decoder check covers the roster, direct weight writes, and timelocked commitments and reveals. It uses historical Bittensor runtime metadata and synthetic payloads with network connections blocked.

```sh
GPU_SUBNET_REQUIRE_SDK_CHECK=1 uv run --extra chain \
  python -m unittest discover -s tests -p 'test_sdk_decoder.py' -v
```

## Bittensor connection

The `chain` extra pins Bittensor SDK 11.3.2. Set `BITTENSOR_NETWORK` to the intended chain name or websocket URL and `SUBNET_NETUID` to its subnet number. The roster command takes the latest finalized roster by default. Use `--block` to read a specific finalized snapshot. The JSON includes all registered slots and lists hotkeys with validator permits separately. Save the output at the report's end block to use it as `--snapshot` for offline replay.

```sh
uv run --extra chain gpu-subnet-chain \
  --network "$BITTENSOR_NETWORK" --netuid "$SUBNET_NETUID" roster
```

The weights command uses a signed report file with a real finalized block anchor on the selected chain. Set the window width and maximum acceptable age in blocks for the scoring policy. Use the wallet and hotkey names of a registered validator with a permit.

```sh
uv run --extra chain gpu-subnet-chain \
  --network "$BITTENSOR_NETWORK" --netuid "$SUBNET_NETUID" weights \
  --report report.json --pool-public-key pool-public-key.hex \
  --window-blocks "$REPORT_WINDOW_BLOCKS" --max-report-age-blocks "$REPORT_MAX_AGE_BLOCKS" \
  --wallet "$VALIDATOR_WALLET" --hotkey "$VALIDATOR_HOTKEY"
```

This command previews the transaction by default. When ready to sign and submit, add `--submit` to the weights command. The weight version key defaults to `0`. Set `--version-key` to the version used by the deployed scoring policy if the subnet requires a higher key. The adapter uses mechanism `0`.

The validator scores against the finalized roster at the report boundary and maps eligible hotkeys to current UIDs. The plan shows `encoded_weights`, the exact 16-bit vector used for the direct call or timelocked commitment. The encoder clips with exact arithmetic and retains every positive eligible target that fits the cap. The SDK checks the encoded vector against current subnet limits when building the transaction.

For submission, the transaction uses an eight-block mortal era. The transport checks target registrations after signing and immediately before broadcast. After finalization, the receipt compares the targets with the roster at the exact inclusion block. `submission_needs_review` preserves the original receipt when that check finds a mismatch or the inclusion roster is unavailable. The chain transaction carries UID numbers, so a change between broadcast and inclusion can still affect attribution. The inclusion check reads the block's post-state. A `commit_queued` receipt includes the reveal round. Reveal and epoch application are separate from the inclusion check. Reconcile any unconfirmed or flagged receipt before retrying.

### Submission recovery

Before broadcasting, the validator commits the signed transaction hash, nonce, window, target registrations, and encoded weights to the private SQLite journal at `~/.local/state/gpu-subnet/submissions.sqlite3`. The submit command prints a short receipt. Use the same journal for each run of a validator. Processes sharing that journal serialize signing and submission by chain and hotkey. If a submission is already active for that hotkey on the same chain, a competing attempt exits before signing. The journal rejects any window older than the latest one reserved for the same chain, subnet, mechanism, and validator hotkey. A pending or successful attempt blocks another submission for the same window end, even if the report digest changes. The journal retains all attempts. Retries require an explicit command.

The finalization watch has a 180-second deadline after the journal records the attempt. A timeout returns `submission_unconfirmed`. If the watch stops and the transaction's fate is unknown, the journal blocks further signing for that chain and hotkey across subnets. Reconcile the earlier attempt to establish inclusion or expiration. A confirmed rejection also clears the signing block.

`history` lists transaction hashes and statuses offline. `reconcile` reads finalized chain state and saves the result privately. An `inclusion_verified` status records a match in a finalized block while dispatch or the follow-up audit is still open. Use `--journal` on all three commands if you store the journal elsewhere.

`reconcile` prints the saved readback as JSON. Exit code `0` means verified weight application, including a verified reveal. Exit code `1` means the attempt is awaiting finality, has verified inclusion with an audit still pending, or has a commitment still queued. Exit code `2` means the result needs attention, including a mismatch, unconfirmed evidence, dispatch failure, expiration, or a command error.

```sh
uv run gpu-subnet-chain history
uv run --extra chain gpu-subnet-chain \
  --network "$BITTENSOR_NETWORK" --netuid "$SUBNET_NETUID" reconcile --tx-hash "$SUBMISSION_HASH"
```

Submission pins the real-time checks and signing to the selected RPC endpoint so the journal can bound the transaction's inclusion window. Reconciliation uses one RPC connection for finalized heights and their block hashes. If the connection changes during those reads, retry the command. Reconciliation saves the exact transaction match before decoding dispatch events or checking the stored weight row, roster, or commitment queue. For a Yuma timelocked commitment, it checks which queue entry disappeared and matches the reveal and the stored weights. Ambiguous or unsupported reveal layouts stay unconfirmed.

Historical transaction lookup uses the SDK's configured archive endpoints for exact block hashes when the block body is unavailable or the primary reports pruned state. For a custom endpoint without a configured archive, use an archive-capable endpoint to reconcile older attempts. If a later readback disputes previously observed inclusion or a successful receipt, the journal flags the conflict and blocks retries for that window. Only a proven dispatch failure or a complete finalized search showing expiration permits a retry of the latest reserved window. Epoch rewards require a separate check.

## Scores API capture

Once the pool provides the endpoint and request parameters, set `SCORES_URL` to the full HTTPS URL. `capture` performs one GET and saves the response body and ordered header pairs. The example stores captures in a private directory outside the repository. When the pool documents a credential header, use `--header-env Header-Name=ENV_VAR` to load its value from the environment. Redirects, HTTP errors, malformed response framing, and unsupported transfer encodings fail the capture. Valid HTTP trailers are saved separately from headers in capture format version 2. Responses without trailers use version 1.

```sh
scores_capture_dir="$HOME/.local/state/gpu-subnet/captures"
mkdir -p -m 700 "$scores_capture_dir"
scores_capture_path="$scores_capture_dir/scores-capture.json"
uv run gpu-subnet-scores capture --url "$SCORES_URL" --output "$scores_capture_path"
uv run gpu-subnet-scores inspect --input "$scores_capture_path"
```

`inspect` runs offline and prints the status, body size and digest, and header names. Both commands label the response `unverified_capture`. Use a fresh filename for each capture.

For a capture containing a signed report in the prototype format below, replace `--report examples/report.json` in the offline example above with `--capture "$scores_capture_path"`. The verification key, roster snapshot, and expected window width are still required. Bob Labs' signature, window, and accounting rules are needed to use their format for scoring.

## Prototype input contract

The report envelope contains `payload` and `signature`. The payload binds the schema version, chain genesis hash, netuid, and half-open block window `[start_block, end_block)`. The separately trusted snapshot is pinned at `end_block`, and its block hash must match `end_block_hash` in the report. The configured window size must equal the reported width.

The signature is lowercase hex Ed25519 over the payload serialized as UTF-8 JSON with keys sorted, non-ASCII characters escaped, separators `,` and `:`, and no trailing newline. The public key file holds the trusted 32-byte key in lowercase hex. `report_digest` is the SHA-256 of the signed payload bytes, and `snapshot_digest` is the SHA-256 of the input snapshot file. Chain hashes are lowercase `0x`-prefixed 32-byte hex strings.

Each report row contains a hotkey, its registration block, and a non-negative integer amount of accepted work. The preview assigns each positive amount to the corresponding eligible UID in the snapshot, provided the same registration was active before the window ended. The receipt's `weights` field holds raw relative scores. The chain plan lists the capped integer vector under `encoded_weights`.

The input contract and the accepted-work scoring rule are prototype choices. A valid signature authenticates the pool's totals. Share-level verification requires proof material and attribution receipts. To integrate Bob Labs, the next inputs are their actual report signature format, work-unit definition, and a sample report with its share evidence.
