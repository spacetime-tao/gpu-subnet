import argparse
import hashlib
import json
import sys
from pathlib import Path

from .evidence import MAX_INPUT_BYTES, load_report, read_bounded
from .scores_capture import load_capture
from .weights import load_snapshot, preview_weights


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Preview GPU subnet weights offline.")
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--report", type=Path, help="signed work report JSON")
    source.add_argument("--capture", type=Path, help="saved response with a prototype-format report")
    parser.add_argument("--snapshot", type=Path, required=True, help="trusted miner snapshot JSON")
    parser.add_argument("--pool-public-key", type=Path, required=True, help="trusted Ed25519 key file")
    parser.add_argument("--window-blocks", type=int, required=True, help="expected number of blocks")
    args = parser.parse_args(argv)

    try:
        pool_public_key = read_bounded(args.pool_public_key, 80).decode("ascii").rstrip("\r\n")
        report_bytes = (
            load_capture(args.capture).body
            if args.capture is not None
            else read_bounded(args.report, MAX_INPUT_BYTES)
        )
        report = load_report(report_bytes, pool_public_key)
        snapshot_bytes = read_bounded(args.snapshot, MAX_INPUT_BYTES)
        snapshot = load_snapshot(snapshot_bytes)
        weights = preview_weights(report, snapshot, args.window_blocks)
    except (OSError, ValueError) as error:
        print(f"Preview rejected: {error}", file=sys.stderr)
        return 2

    receipt = {
        "mode": "offline_preview",
        "status": "preview_ready" if weights else "no_eligible_work",
        "scoring_policy": "accepted_work_v1",
        "report_digest": report.digest,
        "snapshot_digest": hashlib.sha256(snapshot_bytes).hexdigest(),
        "genesis_hash": snapshot.genesis_hash,
        "netuid": snapshot.netuid,
        "start_block": report.start_block,
        "end_block": report.end_block,
        "end_block_hash": snapshot.block_hash,
        "weights": weights,
    }
    print(json.dumps(receipt, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
