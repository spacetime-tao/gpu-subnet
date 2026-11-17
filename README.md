# GPU subnet validator

The subnet is designed to reward miners for verified TensorCash work credited by the Bob Labs pool. Miners run the Bob Labs package and connect to the pool over an outbound WebSocket. The same GPUs can also serve customer inference requests through the pool.

## Paid inference

Paid inference means customers pay to send prompts to a model and receive responses. Bob Labs' design routes requests from a customer listing through its OpenAI-compatible inference gateway and pool to the rigs over their existing WebSocket connections. Bob Labs operates the serving infrastructure. The subnet team owns the listing, pricing, and billing. The first listing still needs its gateway connection details and a way to reconcile customer usage and charges.

## Project status

- **Built in this repo.** The validator fetches and verifies signed Bob Labs scores, maps eligible hotkeys to Bittensor UIDs, and prepares unsigned weight plans. Saved reports can be replayed offline. The Bob Labs commands support cadence-based polling and explicitly enabled weight submissions with a private journal and chain readback. The original block-anchored prototype has its own report format.
- **Still open.** Connect to the pilot pool, confirm the operator settings and report attribution policy, and verify the path from a bound rig to on-chain weights. For paid inference, connect the first listing to Bob Labs' gateway and configure the customer usage and billing workflow.

The current weight formula uses verified TensorCash work and the reported invalid-work rate. Bob Labs' report schema includes inference metrics such as successful and failed requests, time to first token, and tokens per second. Using those metrics for Bittensor rewards would be a separate scoring decision.

The report and roster in `examples/` are synthetic prototype inputs. Run the examples from the project directory with Python 3.11 or newer and `uv` installed.

## Bob Labs scores

The validator checks the pinned Ed25519 key and verifies the signature over the exact UTF-8 bytes in the envelope's `report` string before parsing it. It checks the schema version, subnet number, and Unix-second window. The default window is 86,400 seconds. The scoring rule uses `verified_work * (1 - invalid_rate)`. The two inputs support up to six decimal places. Work must be nonnegative and at most the unsigned 64-bit maximum. The invalid rate must be between zero and one. The pool's credited work already excludes shares it zeroed after audit. The validator matches miner hotkeys against the selected roster, excludes the subnet owner, drops normalized shares strictly below 0.0001, and renormalizes the remaining scores. The signature authenticates the pool's accounting. Independent share verification would require separate proof and attribution data.

### Capture a response

Set `API_BASE` to the HTTPS base URL supplied by Bob Labs. Set `SUBNET_NETUID` to the agreed subnet number and load `SCORES_TOKEN` into the environment through your secret store. Save the pool's public key in `pool-public-key.hex` in the private directory below after confirming the key with Bob Labs through a separate trusted channel. The key file contains the 32-byte key as hex.

```sh
umask 077
gpu_subnet_dir="$HOME/.local/state/gpu-subnet"
mkdir -p -m 700 "$gpu_subnet_dir/captures"
scores_capture_path="$gpu_subnet_dir/captures/scores-capture-$(date -u +%Y%m%dT%H%M%SZ).json"

uv run gpu-subnet-scores capture \
  --api-base "$API_BASE" --netuid "$SUBNET_NETUID" --window-seconds 86400 \
  --output "$scores_capture_path"
uv run gpu-subnet-scores inspect --input "$scores_capture_path"
```

`--api-base` makes one HTTPS GET to `/subnet/scores` with the subnet number and window in the query and uses `SCORES_TOKEN` as a bearer credential. The generic `--url` mode takes a full HTTPS URL with its query parameters and supports `--header-env Header-Name=ENV_VAR` to load a request header from the environment. Use a fresh filename for each capture.

The capture stores the response body and ordered header pairs. Redirects, HTTP errors, malformed response framing, and unsupported transfer encodings fail the capture. Valid HTTP trailers are stored separately in capture format version 2. Responses without trailers use version 1. Both commands label the file `unverified_capture`. The offline `inspect` command prints its status, body size and digest, and header names.

### Replay a signed report offline

Use a trusted finalized roster snapshot for the report you are reviewing. The `roster` command exports the owner hotkey required by this path. Save its JSON outside the repository with the original signed report or capture and the pinned key used for that report.

```sh
uv run gpu-subnet-validate --format bob-v1 \
  --capture "$scores_capture_path" \
  --snapshot "$gpu_subnet_dir/roster-private.json" \
  --pool-public-key "$gpu_subnet_dir/pool-public-key.hex" \
  --window-seconds 86400
```

Use `--report "$REPORT_PATH"` in place of `--capture` if you have the signed envelope JSON. Historical replay uses the recorded scoring window. Pass `--validator-hotkey "$VALIDATOR_HOTKEY_SS58"` to mirror the chain planner's exclusion of the selected validator.

### Plan Bittensor weights

Set `BITTENSOR_NETWORK` to the intended chain name or WebSocket URL. Set `REPORT_MAX_AGE_SECONDS` to the maximum age you will accept between the signed window end and the local clock. The planner rejects timestamps in the future. Use the wallet and hotkey names of a registered validator with a permit.

```sh
uv run --extra chain gpu-subnet-chain \
  --network "$BITTENSOR_NETWORK" --netuid "$SUBNET_NETUID" bob-weights \
  --capture "$scores_capture_path" \
  --pool-public-key "$gpu_subnet_dir/pool-public-key.hex" \
  --window-seconds 86400 --max-report-age-seconds "$REPORT_MAX_AGE_SECONDS" \
  --wallet "$VALIDATOR_WALLET" --hotkey "$VALIDATOR_HOTKEY"
```

`bob-weights` uses the roster at the current best block and pins the read to that block hash. It excludes the selected validator as well as the subnet owner and outputs an unsigned plan by default. Use `--report` for a signed envelope JSON and `--version-key` when the subnet requires a version key above the default of `0`.

The report attributes work to a hotkey over the whole window. The validator follows Bob Labs' reference policy and scores each hotkey against its current registration. If the same hotkey re-registers during the window, its aggregate may still include work from its previous registration. Confirm the pool's treatment of those totals before the pilot.

### Poll for new reports

`bob-loop` takes the same scores origin and bearer credential as `capture`. It reads the subnet's actual tempo, weight rate limit, and last validator update to determine when to poll. The example runs one read-only poll and prints a JSON line with the result. Omit `--max-polls` to keep polling. `--timeout` sets the scores HTTP timeout in seconds.

```sh
uv run --extra chain gpu-subnet-chain \
  --network "$BITTENSOR_NETWORK" --netuid "$SUBNET_NETUID" bob-loop \
  --api-base "$API_BASE" --pool-public-key "$gpu_subnet_dir/pool-public-key.hex" \
  --window-seconds 86400 --max-report-age-seconds "$REPORT_MAX_AGE_SECONDS" \
  --wallet "$VALIDATOR_WALLET" --hotkey "$VALIDATOR_HOTKEY" --max-polls 1
```

Run one polling process per validator hotkey. The loop skips cached or older windows, stale or future reports, and windows with no eligible work. It stops on a failed or ambiguous submission and refuses to sign while an earlier attempt still needs reconciliation. Review the receipt and reconcile the earlier attempt before trying again. The loop does not retry weight submissions automatically.

### Enable Bob Labs weight submission

Both `bob-weights` and `bob-loop` require explicit `--submit --genesis-hash "$CHAIN_GENESIS_HASH"` to sign and broadcast. The genesis hash is the independently confirmed `0x`-prefixed hash of the target chain. Use the same private submission journal for both commands. Add `--journal /path/to/submissions.sqlite3` when using a custom location and pass the same path to `history` and `reconcile`.

The journal records signed Unix-second windows separately from prototype block windows and migrates existing journals in place. A reserved or completed timestamp window prevents another submission for the same end timestamp even if the pool reissues the report with a different digest. Both formats share the chain-and-hotkey lock for signing and nonce use. The validator vetoes a send if a target registration, the subnet owner, or the target weights change after planning. Retries require a manual submission after reconciliation proves that the earlier attempt can be retried.

## Miner setup

Each rig needs an RTX 5090, the Bob Labs package with the engine and weights, and a hotkey registered on the subnet. Install the package, obtain a per-worker challenge using Bob Labs' `hotkey_bind` tool, sign it with the registered hotkey using `btcli wallet sign --use-hotkey`, and exchange the signed challenge for a bind token. Keep the signing key with the wallet. Configure the Bob Labs service with the pool WebSocket URL, a unique worker ID, the bind token or its file path, and the shared join token. The installer supplies the systemd service. The miner needs no inbound port or Bittensor axon.

The join token opens the pool connection. The per-worker bind token links that worker's scores to the registered hotkey. Bob Labs' handoff marked bind-token handling in the miner's initial `HELLO` as pending. Ask Bob Labs which release supports it and what mapping they will use for pilot rigs if it is still pending.

## Pilot dependencies

- Get the scores base URL and bearer token, the pinned public key and its rotation procedure, and a representative signed scores fixture with its verification key. Confirm how the pool issues corrected reports and represents an empty window.
- Get the pool WebSocket URL and join token, the release-matched miner installer and bind tool, and the reference validator and owner bootstrap for review. Keep vendor materials and all real credentials, captures, wallet files, and submission journals outside the repository.
- Agree on the chain, subnet number, signing-key scope, acceptable report age, and scoring policy. The signed Bob Labs report includes a netuid and a timestamp window. Confirm which chain each signing key covers and whether the pool's per-hotkey window totals carry work across re-registration. The advertised 60-second cache and 24-hour scoring window describe separate aspects of the feed. Choose a maximum report age that fits the pool's actual report timing.
- Review Bob Labs' suggested starting settings of a 360-block tempo, at least 24 hours of immunity, up to 256 UIDs, and commit-reveal initially off. Check the subnet's weight rate limit and minimum destinations against the planned validator cadence and pilot roster.
- Confirm the operator procedures for a first submission, reconciliation, and the end-to-end verification of intended weights. Confirm the customer listing's routing, usage records, and supported request behavior with Bob Labs before offering paid inference.

## Run the offline prototype example

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

## Bittensor roster and prototype weights

The `chain` extra pins Bittensor SDK 11.3.2. Set `BITTENSOR_NETWORK` to the intended chain name or WebSocket URL and `SUBNET_NETUID` to its subnet number. The roster command takes the latest finalized roster by default. Use `--block` to read a specific finalized snapshot. The JSON includes the owner hotkey, all registered slots, and a separate list of hotkeys with validator permits. For prototype replay, save the roster at the signed report's end block.

```sh
umask 077
gpu_subnet_dir="$HOME/.local/state/gpu-subnet"
mkdir -p -m 700 "$gpu_subnet_dir"
uv run --extra chain gpu-subnet-chain \
  --network "$BITTENSOR_NETWORK" --netuid "$SUBNET_NETUID" roster \
  > "$gpu_subnet_dir/roster-private.json"
```

The prototype `weights` command uses a signed prototype report with a real finalized block anchor on the selected chain. Set the window width and maximum acceptable age in blocks for the scoring policy. Use the wallet and hotkey names of a registered validator with a permit.

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

`history` lists transaction hashes and statuses offline. `reconcile` reads finalized chain state and saves the result privately. An `inclusion_verified` status records a match in a finalized block while dispatch or the follow-up audit is still open. Use the same `--journal` path on the submission and recovery commands if you store the journal elsewhere.

`reconcile` prints the saved readback as JSON. Exit code `0` means verified weight application, including a verified reveal. Exit code `1` means the attempt is awaiting finality, has verified inclusion with an audit still pending, or has a commitment still queued. Exit code `2` means the result needs attention, including a mismatch, unconfirmed evidence, dispatch failure, expiration, or a command error.

```sh
uv run gpu-subnet-chain history
uv run --extra chain gpu-subnet-chain \
  --network "$BITTENSOR_NETWORK" --netuid "$SUBNET_NETUID" reconcile --tx-hash "$SUBMISSION_HASH"
```

Submission pins the real-time checks and signing to the selected RPC endpoint so the journal can bound the transaction's inclusion window. Reconciliation uses one RPC connection for finalized heights and their block hashes. If the connection changes during those reads, retry the command. Reconciliation saves the exact transaction match before decoding dispatch events or checking the stored weight row, roster, or commitment queue. For a Yuma timelocked commitment, it checks which queue entry disappeared and matches the reveal and the stored weights. Ambiguous or unsupported reveal layouts stay unconfirmed.

Historical transaction lookup uses the SDK's configured archive endpoints for exact block hashes when the block body is unavailable or the primary reports pruned state. For a custom endpoint without a configured archive, use an archive-capable endpoint to reconcile older attempts. If a later readback disputes previously observed inclusion or a successful receipt, the journal flags the conflict and blocks retries for that window. Only a proven dispatch failure or a complete finalized search showing expiration permits a retry of the latest reserved window. Epoch rewards require a separate check.

## Prototype input contract

The report envelope contains `payload` and `signature`. The payload binds the schema version, chain genesis hash, netuid, and half-open block window `[start_block, end_block)`. The separately trusted snapshot is pinned at `end_block`, and its block hash must match `end_block_hash` in the report. The configured window size must equal the reported width.

The signature is lowercase hex Ed25519 over the payload serialized as UTF-8 JSON with keys sorted, non-ASCII characters escaped, separators `,` and `:`, and no trailing newline. The public key file holds the trusted 32-byte key in lowercase hex. `report_digest` is the SHA-256 of the signed payload bytes, and `snapshot_digest` is the SHA-256 of the input snapshot file. Chain hashes are lowercase `0x`-prefixed 32-byte hex strings.

Each report row contains a hotkey, its registration block, and a non-negative integer amount of accepted work. The preview assigns each positive amount to the corresponding eligible UID in the snapshot, provided the same registration was active before the window ended. The receipt's `weights` field holds raw relative scores. The chain plan lists the capped integer vector under `encoded_weights`.

For a capture containing a signed prototype report, replace `--report examples/report.json` in the offline example with `--capture "$scores_capture_path"`. Use the trusted verification key, the matching roster snapshot, and the expected block window.
