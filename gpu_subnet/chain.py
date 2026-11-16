"""Connect signed report scoring to Bittensor roster reads and weight intents."""

import argparse
import asyncio
import json
import sys
from dataclasses import asdict
from pathlib import Path

from .evidence import MAX_INPUT_BYTES, WorkReport, load_report, read_bounded
from .journal import SubmissionJournal
from .readback import reconcile_submission
from .roster import ChainError, Roster, read_roster
from .submission import prepare_submission, submit_weights
from .uid_guard import make_guarded_client
from .weights import MinerSlot, preview_weights

_SDK_VERSION = "11.3.2"
_DEFAULT_JOURNAL = Path.home() / ".local/state/gpu-subnet/submissions.sqlite3"


def _current_targets(
    roster: Roster,
    report: WorkReport,
    scores_by_registration: dict[tuple[str, int], int],
    validator_hotkey: str,
    max_report_age_blocks: int,
) -> tuple[MinerSlot, ...]:
    snapshot = roster.snapshot
    if (snapshot.genesis_hash, snapshot.netuid) != (report.genesis_hash, report.netuid):
        raise ChainError("the current roster is on a different chain or subnet")
    age = snapshot.block - report.end_block
    if not 0 <= age <= max_report_age_blocks:
        raise ChainError("the report is outside the configured maximum age in blocks")
    if validator_hotkey not in roster.validator_hotkeys:
        raise ChainError("the selected hotkey has no validator permit on this subnet")
    return tuple(
        slot
        for slot in sorted(snapshot.miners, key=lambda slot: slot.uid)
        if slot.hotkey != validator_hotkey
        and (slot.hotkey, slot.registered_at) in scores_by_registration
    )


async def run_weights(
    sdk,
    client,
    wallet,
    report: WorkReport,
    *,
    netuid: int,
    window_blocks: int,
    max_report_age_blocks: int,
    version_key: int = 0,
    submit: bool = False,
    journal: SubmissionJournal | None = None,
) -> dict:
    """Preview or explicitly submit weights for one authenticated report."""
    if netuid != report.netuid:
        raise ChainError("the report is for a different subnet than the one selected")
    if type(max_report_age_blocks) is not int or max_report_age_blocks < 0:
        raise ChainError("maximum report age must be a non-negative number of blocks")
    if type(submit) is not bool:
        raise ChainError("submit must be explicitly true or false")
    if submit and journal is None:
        raise ChainError("weight submission requires a private submission journal")

    anchored = await read_roster(client, netuid, block=report.end_block)
    historical_weights = preview_weights(report, anchored.snapshot, window_blocks)
    scores_by_registration = {
        (slot.hotkey, slot.registered_at): historical_weights[slot.uid]
        for slot in anchored.snapshot.miners
        if slot.uid in historical_weights
    }
    validator_hotkey = sdk.public_view(wallet, "hotkey").ss58_address
    current = await read_roster(client, netuid, finalized=False)
    targets = _current_targets(
        current, report, scores_by_registration, validator_hotkey, max_report_age_blocks
    )
    weights = {slot.uid: scores_by_registration[slot.hotkey, slot.registered_at] for slot in targets}
    receipt = {
        "status": "preview_ready" if weights else "no_eligible_work",
        "scoring_policy": "accepted_work_v1",
        "genesis_hash": report.genesis_hash,
        "netuid": netuid,
        "validator_hotkey": validator_hotkey,
        "start_block": report.start_block,
        "end_block": report.end_block,
        "end_block_hash": report.end_block_hash,
        "report_digest": report.digest,
        "roster_block": current.snapshot.block,
        "roster_block_hash": current.snapshot.block_hash,
        "targets": [asdict(slot) for slot in targets],
        "weights": weights,
    }
    if not weights:
        return receipt

    intent, plan = await prepare_submission(
        sdk, client, wallet, netuid=netuid, weights=weights, version_key=version_key
    )
    if plan.get("signer_address") != validator_hotkey:
        raise ChainError("the SDK plan signer differs from the selected validator hotkey")
    receipt["plan"] = plan
    if not submit:
        return receipt

    tx_hash = None

    async def before_broadcast(extrinsic, signer_address: str) -> None:
        nonlocal tx_hash
        if signer_address != validator_hotkey:
            raise ChainError("signed transaction hotkey differs from the selected validator")
        latest = await read_roster(client, netuid, finalized=False)
        latest_targets = _current_targets(
            latest, report, scores_by_registration, validator_hotkey, max_report_age_blocks
        )
        head_rewound = latest.snapshot.block < current.snapshot.block
        head_replaced = (
            latest.snapshot.block == current.snapshot.block
            and latest.snapshot.block_hash != current.snapshot.block_hash
        )
        if (
            latest_targets != targets or head_rewound or head_replaced
            or latest.snapshot.block < finalized_before_signing
        ):
            raise ChainError("the roster changed before broadcast; prepare a fresh weight set")
        receipt["roster_block"] = latest.snapshot.block
        receipt["roster_block_hash"] = latest.snapshot.block_hash
        journal.record_attempt({
            "extrinsic_hash": extrinsic.extrinsic_hash,
            "nonce": extrinsic.nonce,
            "genesis_hash": report.genesis_hash,
            "netuid": netuid,
            "mechid": intent.mechid,
            "validator_hotkey": validator_hotkey,
            "start_block": report.start_block,
            "end_block": report.end_block,
            "end_block_hash": report.end_block_hash,
            "report_digest": report.digest,
            "encoded_weights": plan["encoded_weights"],
            "targets": receipt["targets"],
            "scan_start_block": finalized_before_signing + 1,
            "broadcast_head_block": latest.snapshot.block,
            "broadcast_head_hash": latest.snapshot.block_hash,
            "transaction_period_blocks": plan["transaction_period_blocks"],
        })
        tx_hash = extrinsic.extrinsic_hash

    with journal.submission_slot(
        genesis_hash=report.genesis_hash, netuid=netuid, mechid=intent.mechid,
        hotkey=validator_hotkey, end_block=report.end_block,
    ):
        # The SDK anchors the mortal era at a finalized block during signing.
        # Observing finality beforehand gives recovery a conservative scan start.
        finalized_before_signing = await client.finalized_block()
        result = await submit_weights(client, wallet, intent, before_broadcast=before_broadcast)
        if tx_hash is not None:
            journal.save_receipt(tx_hash, result)
            receipt["extrinsic_hash"] = tx_hash
    receipt.update(status=result["status"], submission=result)
    if result["status"] in {"weights_submitted", "commit_queued"}:
        audit = await _audit_inclusion_roster(
            sdk, client, netuid, report.genesis_hash, result["block_hash"], targets
        )
        receipt["inclusion_roster"] = audit
        if audit["status"] != "matched":
            receipt["status"] = "submission_needs_review"
        if tx_hash is not None:
            journal.save_receipt(tx_hash, {
                **result, "status": receipt["status"], "inclusion_roster": audit,
            })
    return receipt


async def _audit_inclusion_roster(sdk, client, netuid, genesis_hash, block_hash, targets) -> dict:
    """Compare target registrations with the post-state of the inclusion block."""
    try:
        roster = await read_roster(client, netuid, block_hash=block_hash)
        if roster.snapshot.genesis_hash != genesis_hash:
            raise ChainError("inclusion roster is on a different chain")
    except (OSError, ValueError, sdk.BittensorError) as error:
        return {"status": "unavailable", "block_hash": block_hash, "error": str(error)}

    slots = {slot.uid: slot for slot in roster.snapshot.miners}
    changed_uids = [target.uid for target in targets if slots.get(target.uid) != target]
    return {
        "status": "mismatch" if changed_uids else "matched",
        "block": roster.snapshot.block,
        "block_hash": roster.snapshot.block_hash,
        "changed_uids": changed_uids,
    }


async def _run_command(sdk, args: argparse.Namespace, report: WorkReport | None) -> dict:
    if args.command == "reconcile":
        journal = _open_journal(args.journal)
        entry = journal.get(args.tx_hash)
        if entry["attempt"]["netuid"] != args.netuid:
            raise ChainError("the recorded transaction is for a different subnet")
        async with make_guarded_client(sdk, args.network, pin_finality=True) as client:
            readback = await reconcile_submission(
                client, entry,
                save_inclusion=lambda inclusion: journal.save_readback(args.tx_hash, inclusion),
            )
        journal.save_readback(args.tx_hash, readback)
        return {"extrinsic_hash": args.tx_hash, **journal.get(args.tx_hash)["readback"]}

    sending = args.command == "weights" and args.submit
    # Signing and the following head check must use a coherent RPC view to
    # bound the signed era. Historical readbacks can still use archive nodes.
    async with make_guarded_client(
        sdk, args.network, allow_failover=not sending, pin_finality=True,
    ) as client:
        if args.command == "roster":
            roster = await read_roster(client, args.netuid, block=args.block)
            return {
                **asdict(roster.snapshot),
                "validator_hotkeys": sorted(roster.validator_hotkeys),
            }

        wallet = sdk.Wallet(name=args.wallet, hotkey=args.hotkey)
        journal = _open_journal(args.journal, create=True) if args.submit else None
        return await run_weights(
            sdk,
            client,
            wallet,
            report,
            netuid=args.netuid,
            window_blocks=args.window_blocks,
            max_report_age_blocks=args.max_report_age_blocks,
            version_key=args.version_key,
            submit=args.submit,
            journal=journal,
        )


def _open_journal(path: Path, *, create: bool = False) -> SubmissionJournal:
    path = path.expanduser()
    if create:
        path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    elif not path.is_file():
        raise ChainError("the submission journal does not exist")
    return SubmissionJournal(path)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Read a Bittensor roster or prepare weights.")
    parser.add_argument("--network", help="chain network name or websocket URL")
    parser.add_argument("--netuid", type=int, help="subnet number")
    subcommands = parser.add_subparsers(dest="command", required=True)

    roster = subcommands.add_parser("roster", help="read a finalized roster without a wallet")
    roster.add_argument("--block", type=int, help="finalized block height (default latest)")

    weights = subcommands.add_parser("weights", help="preview a weight intent for one signed report")
    weights.add_argument("--report", type=Path, required=True, help="signed work report JSON")
    weights.add_argument("--pool-public-key", type=Path, required=True, help="trusted pool key file")
    weights.add_argument("--window-blocks", type=int, required=True, help="expected report width")
    weights.add_argument("--max-report-age-blocks", type=int, required=True, help="age at chain head")
    weights.add_argument("--wallet", required=True, help="validator wallet name")
    weights.add_argument("--hotkey", required=True, help="validator hotkey name within the wallet")
    weights.add_argument("--version-key", type=int, default=0, help="subnet scoring version key")
    weights.add_argument("--submit", action="store_true", help="sign and submit the weight intent")
    weights.add_argument("--journal", type=Path, default=_DEFAULT_JOURNAL, help="private SQLite file")

    reconcile = subcommands.add_parser("reconcile", help="read back a recorded transaction")
    reconcile.add_argument("--tx-hash", required=True, help="hash of the signed transaction")
    reconcile.add_argument("--journal", type=Path, default=_DEFAULT_JOURNAL, help="private SQLite file")

    history = subcommands.add_parser("history", help="list recorded attempts offline")
    history.add_argument("--journal", type=Path, default=_DEFAULT_JOURNAL, help="private SQLite file")
    history.add_argument("--limit", type=int, default=50, help="maximum number of attempts to list")
    args = parser.parse_args(argv)
    if args.netuid is not None and not 0 < args.netuid <= 65_535:
        parser.error("--netuid must be a non-root subnet number")
    if args.command == "roster" and args.block is not None and args.block < 0:
        parser.error("--block must be non-negative")
    if args.command == "history":
        try:
            records = _open_journal(args.journal).list_attempts(netuid=args.netuid, limit=args.limit)
        except (OSError, ValueError) as error:
            print(f"Chain command failed: {error}", file=sys.stderr)
            return 2
        print(json.dumps({"attempts": records}, indent=2))
        return 0
    if args.network is None or args.netuid is None:
        parser.error("--network and --netuid are required for chain commands")

    try:
        import bittensor as sdk
    except ImportError as error:
        print(f"Bittensor SDK unavailable. Install the chain extra. {error}", file=sys.stderr)
        return 2
    if getattr(sdk, "__version__", None) != _SDK_VERSION:
        print(f"Bittensor SDK {_SDK_VERSION} is required. Install the chain extra.", file=sys.stderr)
        return 2

    try:
        report = None
        if args.command == "weights":
            key = read_bounded(args.pool_public_key, 80).decode("ascii").rstrip("\r\n")
            report = load_report(read_bounded(args.report, MAX_INPUT_BYTES), key)
            if report.netuid != args.netuid:
                raise ChainError("the report is for a different subnet than the one selected")
        receipt = asyncio.run(_run_command(sdk, args, report))
    except (OSError, ValueError, sdk.BittensorError) as error:
        print(f"Chain command failed: {error}", file=sys.stderr)
        return 2

    if args.command == "weights" and args.submit:
        # Keep the committed vector in private storage until the chain reveals it.
        visible = {"status", "extrinsic_hash", "submission", "inclusion_roster"}
        receipt = {key: value for key, value in receipt.items() if key in visible}
    print(json.dumps(receipt, indent=2))
    status = receipt.get("status")
    if args.command == "reconcile":
        if status in ("weights_applied", "reveal_applied"):
            return 0
        if status in ("awaiting_finality", "inclusion_verified", "commit_pending"):
            return 1
        return 2
    failed_statuses = {"submission_failed", "submission_unconfirmed", "submission_needs_review"}
    return 2 if status in failed_statuses else 0


if __name__ == "__main__":
    raise SystemExit(main())
