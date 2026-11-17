import argparse
import hashlib
import json
import sys
from pathlib import Path

from .bob_scores import (
    DEFAULT_WINDOW_SECONDS,
    load_bob_report,
    normalized_weights,
    preview_bob_weights,
)
from .evidence import MAX_INPUT_BYTES, load_report, read_bounded
from .scores_capture import load_capture
from .weights import load_snapshot, preview_weights


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Preview GPU subnet weights offline.")
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--report", type=Path, help="signed work report JSON")
    source.add_argument("--capture", type=Path, help="saved scores response")
    parser.add_argument("--format", choices=("prototype", "bob-v1"), default="prototype")
    parser.add_argument("--snapshot", type=Path, required=True, help="trusted miner snapshot JSON")
    parser.add_argument("--pool-public-key", type=Path, required=True, help="trusted Ed25519 key file")
    parser.add_argument("--window-blocks", type=int, help="expected prototype window in blocks")
    parser.add_argument("--window-seconds", type=int, help="expected Bob Labs window (default 86400)")
    parser.add_argument("--validator-hotkey", help="exclude this validator hotkey in Bob Labs mode")
    args = parser.parse_args(argv)
    if args.format == "prototype":
        if args.window_blocks is None:
            parser.error("prototype reports require --window-blocks")
        if args.window_seconds is not None or args.validator_hotkey is not None:
            parser.error("--window-seconds and --validator-hotkey require --format bob-v1")
    elif args.window_blocks is not None:
        parser.error("Bob Labs reports use --window-seconds")

    try:
        pool_public_key = read_bounded(args.pool_public_key, 80).decode("ascii").rstrip("\r\n")
        report_bytes = (
            load_capture(args.capture).body
            if args.capture is not None
            else read_bounded(args.report, MAX_INPUT_BYTES)
        )
        snapshot_bytes = read_bounded(args.snapshot, MAX_INPUT_BYTES)
        snapshot = load_snapshot(snapshot_bytes)
        if args.format == "bob-v1":
            window_seconds = DEFAULT_WINDOW_SECONDS if args.window_seconds is None else args.window_seconds
            report = load_bob_report(
                report_bytes, pool_public_key, netuid=snapshot.netuid, window_seconds=window_seconds,
            )
            weights = preview_bob_weights(report, snapshot, validator_hotkey=args.validator_hotkey)
            scoring = {
                "scoring_policy": "bob_labs_work_v1",
                "start_ts": report.start_ts,
                "end_ts": report.end_ts,
                "roster_block": snapshot.block,
                "roster_block_hash": snapshot.block_hash,
                "normalized_weights": normalized_weights(weights),
            }
        else:
            report = load_report(report_bytes, pool_public_key)
            weights = preview_weights(report, snapshot, args.window_blocks)
            scoring = {
                "scoring_policy": "accepted_work_v1",
                "start_block": report.start_block,
                "end_block": report.end_block,
                "end_block_hash": snapshot.block_hash,
                "weights": weights,
            }
    except (OSError, ValueError) as error:
        print(f"Preview rejected: {error}", file=sys.stderr)
        return 2

    receipt = {
        "mode": "offline_preview",
        "status": "preview_ready" if weights else "no_eligible_work",
        "report_digest": report.digest,
        "snapshot_digest": hashlib.sha256(snapshot_bytes).hexdigest(),
        "genesis_hash": snapshot.genesis_hash,
        "netuid": snapshot.netuid,
        **scoring,
    }
    print(json.dumps(receipt, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
