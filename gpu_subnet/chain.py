"""Connect signed report scoring to Bittensor roster reads and weight intents."""

import argparse
import asyncio
import json
import os
import sys
import time
from contextlib import nullcontext
from dataclasses import asdict
from pathlib import Path

from .bob_loop import FAILED_SUBMISSION_STATUSES, run_bob_loop
from .bob_scores import (
    DEFAULT_WINDOW_SECONDS,
    BobReport,
    fetch_bob_scores,
    load_bob_report,
    normalized_weights,
    preview_bob_weights,
)
from .evidence import MAX_INPUT_BYTES, WorkReport, _chain_hash, _hex_bytes, load_report, read_bounded
from .journal import SubmissionJournal, WindowAlreadyAttempted
from .readback import reconcile_submission
from .roster import ChainError, Roster, read_roster
from .scores_capture import load_capture
from .submission import prepare_submission, submit_weights
from .uid_guard import make_guarded_client
from .weights import MinerSlot, preview_weights

_SDK_VERSION = "11.3.2"
_DEFAULT_JOURNAL = Path.home() / ".local/state/gpu-subnet/submissions.sqlite3"
_MECHID = 0


class BobReportAgeError(ChainError):
    def __init__(self, status: str, message: str):
        super().__init__(message)
        self.status = status


def _check_submission_request(submit: bool, journal: SubmissionJournal | None) -> None:
    if type(submit) is not bool:
        raise ChainError("submit must be explicitly true or false")
    if submit and journal is None:
        raise ChainError("weight submission requires a private submission journal")


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
    _check_submission_request(submit, journal)

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
    window = {
        "start_block": report.start_block,
        "end_block": report.end_block,
        "end_block_hash": report.end_block_hash,
    }
    receipt = {
        "status": "preview_ready" if weights else "no_eligible_work",
        "scoring_policy": "accepted_work_v1",
        "genesis_hash": report.genesis_hash,
        "netuid": netuid,
        "validator_hotkey": validator_hotkey,
        **window,
        "report_digest": report.digest,
        "roster_block": current.snapshot.block,
        "roster_block_hash": current.snapshot.block_hash,
        "targets": [asdict(slot) for slot in targets],
        "weights": weights,
    }

    def check_targets(latest):
        if _current_targets(
            latest, report, scores_by_registration, validator_hotkey, max_report_age_blocks
        ) != targets:
            raise ChainError("the roster changed before broadcast; prepare a fresh weight set")

    return await _finish_weight_plan(
        sdk, client, wallet, current=current, targets=targets, weights=weights, receipt=receipt,
        window=window, check_targets=check_targets, version_key=version_key,
        journal=journal if submit else None,
    )


async def _finish_weight_plan(
    sdk, client, wallet, *, current, targets, weights, receipt, window, check_targets,
    version_key: int, journal: SubmissionJournal | None, allow_retry: bool = True,
) -> dict:
    if not weights:
        return receipt
    netuid = current.snapshot.netuid
    genesis = current.snapshot.genesis_hash
    validator_hotkey = receipt["validator_hotkey"]
    timestamp_window = window.get("window_kind") == "timestamp"
    window_key = (
        {"window_kind": "timestamp", "end_ts": window["end_ts"], "allow_retry": allow_retry}
        if timestamp_window else {"end_block": window["end_block"]}
    )
    tx_hash = None

    async def before_broadcast(extrinsic, signer_address: str) -> None:
        nonlocal tx_hash
        if signer_address != validator_hotkey:
            raise ChainError("signed transaction hotkey differs from the selected validator")
        latest = await read_roster(client, netuid, finalized=False)
        check_targets(latest)
        head_rewound = latest.snapshot.block < current.snapshot.block
        head_replaced = (
            latest.snapshot.block == current.snapshot.block
            and latest.snapshot.block_hash != current.snapshot.block_hash
        )
        if (
            head_rewound or head_replaced or latest.snapshot.block < finalized_before_signing
        ):
            raise ChainError("the roster changed before broadcast; prepare a fresh weight set")
        receipt["roster_block"] = latest.snapshot.block
        receipt["roster_block_hash"] = latest.snapshot.block_hash
        journal.record_attempt({
            "extrinsic_hash": extrinsic.extrinsic_hash,
            "nonce": extrinsic.nonce,
            "genesis_hash": genesis,
            "netuid": netuid,
            "mechid": intent.mechid,
            "validator_hotkey": validator_hotkey,
            **window,
            "report_digest": receipt["report_digest"],
            "encoded_weights": plan["encoded_weights"],
            "targets": receipt["targets"],
            "scan_start_block": finalized_before_signing + 1,
            "broadcast_head_block": latest.snapshot.block,
            "broadcast_head_hash": latest.snapshot.block_hash,
            "transaction_period_blocks": plan["transaction_period_blocks"],
        }, allow_retry=allow_retry)
        tx_hash = extrinsic.extrinsic_hash

    slot = nullcontext() if journal is None else journal.submission_slot(
        genesis_hash=genesis, netuid=netuid, mechid=_MECHID, hotkey=validator_hotkey, **window_key,
    )
    with slot:
        intent, plan = await prepare_submission(
            sdk, client, wallet, netuid=netuid, weights=weights, version_key=version_key,
        )
        if plan.get("signer_address") != validator_hotkey:
            raise ChainError("the SDK plan signer differs from the selected validator hotkey")
        receipt["plan"] = plan
        if journal is None:
            return receipt
        if intent.mechid != _MECHID:
            raise ChainError("the SDK plan uses a different weight mechanism")
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
            sdk, client, netuid, genesis, result["block_hash"], targets,
            exclude_owner=timestamp_window,
        )
        receipt["inclusion_roster"] = audit
        if audit["status"] != "matched":
            receipt["status"] = "submission_needs_review"
        if tx_hash is not None:
            journal.save_receipt(tx_hash, {
                **result, "status": receipt["status"], "inclusion_roster": audit,
            })
    return receipt


async def _audit_inclusion_roster(
    sdk, client, netuid, genesis_hash, block_hash, targets, *, exclude_owner=False,
) -> dict:
    """Compare target registrations with the post-state of the inclusion block."""
    try:
        roster = await read_roster(client, netuid, block_hash=block_hash)
        if roster.snapshot.genesis_hash != genesis_hash:
            raise ChainError("inclusion roster is on a different chain")
        if exclude_owner and roster.snapshot.owner_hotkey is None:
            raise ChainError("the inclusion roster does not identify the subnet owner")
    except (OSError, ValueError, sdk.BittensorError) as error:
        return {"status": "unavailable", "block_hash": block_hash, "error": str(error)}

    slots = {slot.uid: slot for slot in roster.snapshot.miners}
    changed_uids = [
        target.uid for target in targets
        if slots.get(target.uid) != target
        or (exclude_owner and target.hotkey == roster.snapshot.owner_hotkey)
    ]
    return {
        "status": "mismatch" if changed_uids else "matched",
        "block": roster.snapshot.block,
        "block_hash": roster.snapshot.block_hash,
        "changed_uids": changed_uids,
    }


def _check_bob_age(report: BobReport, max_age: int, now: int | None) -> None:
    age = (int(time.time()) if now is None else now) - report.end_ts
    if age < 0:
        raise BobReportAgeError("future_report", "the scores report ends in the future")
    if age > max_age:
        raise BobReportAgeError("stale_report", "the scores report is older than the configured maximum age")


def _bob_targets(roster: Roster, report: BobReport, validator_hotkey: str):
    if validator_hotkey not in roster.validator_hotkeys:
        raise ChainError("the selected hotkey has no validator permit on this subnet")
    weights = preview_bob_weights(report, roster.snapshot, validator_hotkey=validator_hotkey)
    targets = tuple(slot for slot in roster.snapshot.miners if slot.uid in weights)
    return weights, targets


async def run_bob_weights(
    sdk, client, wallet, report: BobReport, *, netuid: int, max_report_age_seconds: int,
    version_key: int = 0, now: int | None = None, submit: bool = False,
    journal: SubmissionJournal | None = None, genesis_hash: str | None = None,
    allow_retry: bool = True,
) -> dict:
    """Preview or explicitly submit weights using authenticated Bob Labs scores."""
    if report.netuid != netuid:
        raise ChainError("the scores report is for a different subnet than the one selected")
    if type(max_report_age_seconds) is not int or max_report_age_seconds < 0:
        raise ChainError("maximum report age must be a non-negative number of seconds")
    _check_submission_request(submit, journal)
    if submit or genesis_hash is not None:
        _chain_hash(genesis_hash, label="expected chain genesis hash")
    _check_bob_age(report, max_report_age_seconds, now)

    roster = await read_roster(client, netuid, finalized=False)
    validator_hotkey = sdk.public_view(wallet, "hotkey").ss58_address
    snapshot = roster.snapshot
    if genesis_hash is not None and snapshot.genesis_hash != genesis_hash:
        raise ChainError("the roster is on a different chain than the configured genesis hash")
    weights, targets = _bob_targets(roster, report, validator_hotkey)
    window = {"window_kind": "timestamp", "start_ts": report.start_ts, "end_ts": report.end_ts}
    receipt = {
        "status": "preview_ready" if weights else "no_eligible_work",
        "scoring_policy": "bob_labs_work_v1",
        "genesis_hash": snapshot.genesis_hash,
        "netuid": netuid,
        "validator_hotkey": validator_hotkey,
        **window,
        "report_digest": report.digest,
        "roster_block": snapshot.block,
        "roster_block_hash": snapshot.block_hash,
        "targets": [asdict(slot) for slot in targets],
        "normalized_weights": normalized_weights(weights),
    }
    def check_targets(latest):
        _check_bob_age(report, max_report_age_seconds, now)
        if latest.snapshot.genesis_hash != snapshot.genesis_hash:
            raise ChainError("the latest roster is on a different chain")
        if (
            latest.snapshot.owner_hotkey != snapshot.owner_hotkey
            or _bob_targets(latest, report, validator_hotkey) != (weights, targets)
        ):
            raise ChainError("the roster or scores changed before broadcast; prepare a fresh weight set")

    return await _finish_weight_plan(
        sdk, client, wallet, current=roster, targets=targets, weights=weights, receipt=receipt,
        window=window, check_targets=check_targets, version_key=version_key,
        journal=journal if submit else None, allow_retry=allow_retry,
    )


def _visible_receipt(receipt: dict, submit: bool) -> dict:
    if not submit:
        return receipt
    # Keep the committed vector in private storage until the chain reveals it.
    visible = {
        "status", "reason", "netuid", "end_ts", "extrinsic_hash", "submission", "inclusion_roster",
    }
    return {key: value for key, value in receipt.items() if key in visible}


async def _poll_bob_reports(sdk, client, wallet, args, journal) -> dict:
    token = os.environ.get("SCORES_TOKEN", "")
    pool_key = read_bounded(args.pool_public_key, 80).decode("ascii").rstrip("\r\n")
    _hex_bytes(pool_key.lower(), 32, label="pool public key")
    if not token:
        raise ChainError("SCORES_TOKEN is missing")
    if args.genesis_hash is not None and await client._substrate.block_hash(0) != args.genesis_hash:
        raise ChainError("the selected chain does not match the configured genesis hash")

    async def fetch_report() -> BobReport:
        response = await asyncio.to_thread(
            fetch_bob_scores, args.api_base, token, netuid=args.netuid,
            window_seconds=args.window_seconds, timeout=args.timeout,
        )
        return load_bob_report(
            response.body, pool_key, netuid=args.netuid, window_seconds=args.window_seconds,
        )

    async def run_report(report: BobReport) -> dict:
        try:
            return await run_bob_weights(
                sdk, client, wallet, report, netuid=args.netuid,
                max_report_age_seconds=args.max_report_age_seconds, version_key=args.version_key,
                submit=args.submit, journal=journal, genesis_hash=args.genesis_hash, allow_retry=False,
            )
        except BobReportAgeError as error:
            return {"status": error.status, "netuid": args.netuid, "end_ts": report.end_ts}
        except WindowAlreadyAttempted as error:
            return {
                "status": "window_skipped", "reason": error.reason,
                "netuid": args.netuid, "end_ts": report.end_ts,
            }

    return await run_bob_loop(
        client, netuid=args.netuid, fetch_report=fetch_report, run_report=run_report,
        validator_hotkey=sdk.public_view(wallet, "hotkey").ss58_address, max_polls=args.max_polls,
        emit=lambda receipt: print(json.dumps(_visible_receipt(receipt, args.submit)), flush=True),
    )


async def _run_command(sdk, args: argparse.Namespace, report: WorkReport | BobReport | None) -> dict:
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

    sending = args.command in ("weights", "bob-weights", "bob-loop") and args.submit
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
        journal = _open_journal(args.journal, create=True) if sending else None
        if args.command == "bob-loop":
            return await _poll_bob_reports(sdk, client, wallet, args, journal)
        if args.command == "bob-weights":
            return await run_bob_weights(
                sdk, client, wallet, report, netuid=args.netuid,
                max_report_age_seconds=args.max_report_age_seconds, version_key=args.version_key,
                submit=args.submit, journal=journal, genesis_hash=args.genesis_hash,
            )
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


def _bob_cli_options(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--pool-public-key", type=Path, required=True, help="trusted pool key file")
    parser.add_argument("--window-seconds", type=int, default=DEFAULT_WINDOW_SECONDS)
    parser.add_argument("--max-report-age-seconds", type=int, required=True)
    parser.add_argument("--wallet", required=True, help="validator wallet name")
    parser.add_argument("--hotkey", required=True, help="validator hotkey name within the wallet")
    parser.add_argument("--version-key", type=int, default=0, help="subnet scoring version key")
    parser.add_argument("--genesis-hash", help="trusted chain genesis hash (required for --submit)")
    parser.add_argument("--submit", action="store_true", help="sign and submit eligible weights")
    parser.add_argument("--journal", type=Path, default=_DEFAULT_JOURNAL, help="private SQLite file")


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

    bob_weights = subcommands.add_parser("bob-weights", help="plan weights from one signed Bob Labs report")
    bob_source = bob_weights.add_mutually_exclusive_group(required=True)
    bob_source.add_argument("--report", type=Path, help="Bob Labs scores envelope JSON")
    bob_source.add_argument("--capture", type=Path, help="saved Bob Labs scores response")
    _bob_cli_options(bob_weights)

    bob_loop = subcommands.add_parser("bob-loop", help="poll signed Bob Labs scores on the subnet cadence")
    _bob_cli_options(bob_loop)
    bob_loop.add_argument("--api-base", required=True, help="Bob Labs HTTPS origin; uses SCORES_TOKEN")
    bob_loop.add_argument("--timeout", type=float, default=30.0, help="scores HTTP timeout in seconds")
    bob_loop.add_argument("--max-polls", type=int, help="stop after this number of reports")

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
    if args.command in ("bob-weights", "bob-loop"):
        if args.submit and args.genesis_hash is None:
            parser.error("Bob Labs --submit requires --genesis-hash")
        if args.genesis_hash is not None:
            try:
                _chain_hash(args.genesis_hash, label="chain genesis hash")
            except ValueError as error:
                parser.error(str(error))
        if not 0 < args.window_seconds < 2**64 or args.max_report_age_seconds < 0:
            parser.error("Bob Labs commands require a positive window and a non-negative report age")
    if args.command == "bob-loop":
        if args.max_polls is not None and args.max_polls < 1:
            parser.error("--max-polls must be positive")
        if not 0 < args.timeout < float("inf"):
            parser.error("--timeout must be positive and finite")

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
        elif args.command == "bob-weights":
            key = read_bounded(args.pool_public_key, 80).decode("ascii").rstrip("\r\n")
            raw = (
                load_capture(args.capture).body
                if args.capture is not None
                else read_bounded(args.report, MAX_INPUT_BYTES)
            )
            report = load_bob_report(raw, key, netuid=args.netuid, window_seconds=args.window_seconds)
        receipt = asyncio.run(_run_command(sdk, args, report))
    except KeyboardInterrupt:
        print("Chain command interrupted. Check history and reconcile any pending submission.", file=sys.stderr)
        return 130
    except (OSError, ValueError, sdk.BittensorError) as error:
        print(f"Chain command failed: {error}", file=sys.stderr)
        return 2

    if args.command != "bob-loop":
        print(json.dumps(_visible_receipt(receipt, getattr(args, "submit", False)), indent=2))
    status = receipt.get("status")
    if args.command == "reconcile":
        if status in ("weights_applied", "reveal_applied"):
            return 0
        if status in ("awaiting_finality", "inclusion_verified", "commit_pending"):
            return 1
        return 2
    return 2 if status in FAILED_SUBMISSION_STATUSES else 0


if __name__ == "__main__":
    raise SystemExit(main())
