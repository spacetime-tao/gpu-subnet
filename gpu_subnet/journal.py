"""Private, durable records of signed weight transactions and their outcomes."""

import errno
import json
import os
import re
import sqlite3
import stat
from collections.abc import Iterator
from contextlib import closing, contextmanager
from hashlib import sha256
from pathlib import Path

from .evidence import ReportError, _chain_hash, _hotkey, _uint
from .readback import (
    _INCLUSION_VERIFIED, _SUCCESSFUL_READBACKS, _SUCCESSFUL_RECEIPTS, _dispatch_outcome,
)

_RETRYABLE = ("dispatch_failed", "expired_unseen")
_APPLIED = ("weights_applied", "reveal_applied")
_INCONCLUSIVE = ("awaiting_finality", "inclusion_unconfirmed", "reveal_unconfirmed")


class JournalError(ValueError):
    """The journal could not safely record or recover a submission."""


class SubmissionJournal:
    def __init__(self, path: Path):
        self.path = path.expanduser().absolute()
        self._device, self._inode = self._prepare_file()
        with self._connection() as connection:
            connection.execute("""
                CREATE TABLE IF NOT EXISTS attempts (
                    extrinsic_hash TEXT PRIMARY KEY,
                    genesis_hash TEXT NOT NULL,
                    netuid INTEGER NOT NULL,
                    mechid INTEGER NOT NULL,
                    validator_hotkey TEXT NOT NULL,
                    start_block INTEGER NOT NULL,
                    end_block INTEGER NOT NULL,
                    broadcast_head_block INTEGER NOT NULL,
                    attempt_json TEXT NOT NULL,
                    receipt_json TEXT,
                    receipt_success INTEGER NOT NULL DEFAULT 0,
                    readback_json TEXT,
                    readback_status TEXT
                )
            """)
            connection.execute("""
                CREATE INDEX IF NOT EXISTS attempts_window
                ON attempts (genesis_hash, netuid, mechid, validator_hotkey, end_block)
            """)

    def _prepare_file(self) -> tuple[int, int]:
        try:
            try:
                descriptor = os.open(self.path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
            except FileExistsError:
                pass
            else:
                try:
                    os.fchmod(descriptor, 0o600)
                finally:
                    os.close(descriptor)
            metadata = self.path.lstat()
        except OSError as error:
            raise JournalError("could not open the private submission journal file") from error
        if not _owner_only_file(metadata):
            raise JournalError("submission journal must be an owner-only regular file")
        return metadata.st_dev, metadata.st_ino

    @contextmanager
    def _connection(self) -> Iterator[sqlite3.Connection]:
        try:
            with closing(sqlite3.connect(self.path)) as connection, connection:
                # In rollback-journal mode this also syncs the directory after
                # removing the rollback file at commit. Return before broadcast
                # only after the transaction context has committed.
                connection.execute("PRAGMA synchronous = EXTRA")
                yield connection
        except sqlite3.Error as error:
            raise JournalError("could not read or update the submission journal") from error

    @contextmanager
    def submission_slot(
        self, *, genesis_hash: str, netuid: int, mechid: int, hotkey: str, end_block: int
    ) -> Iterator[None]:
        """Keep signing and sending in one order across users of this journal."""
        try:
            import fcntl
        except ImportError as error:
            raise JournalError("weight submission requires local file locking") from error

        # Nonces belong to a hotkey on a chain, even across subnets and mechanisms.
        identity = f"{self._device}:{self._inode}:{genesis_hash}:{hotkey}"
        lock_key = sha256(identity.encode("ascii")).hexdigest()
        lock_path = self.path.with_name(f".submission-{lock_key}.lock")
        try:
            descriptor = os.open(
                lock_path, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600
            )
        except OSError as error:
            raise JournalError("could not open the private submission lock") from error
        try:
            try:
                if not _owner_only_file(os.fstat(descriptor)):
                    raise JournalError("submission lock must be an owner-only regular file")
                fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except OSError as error:
                if error.errno in {errno.EACCES, errno.EAGAIN}:
                    raise JournalError("another weight submission is active for this hotkey") from error
                raise JournalError("could not acquire the private submission lock") from error

            with self._connection() as connection:
                _check_window_available(connection, (genesis_hash, netuid, mechid, hotkey, end_block))
                _check_nonce_available(connection, genesis_hash, hotkey)
            yield
        finally:
            # Keep the lock file in place so contenders always open the same inode.
            os.close(descriptor)

    def record_attempt(self, attempt: dict) -> None:
        """Reserve a scoring-window end and save the signed hash before sending."""
        fields = _attempt_fields(attempt)
        extrinsic_hash, genesis, netuid, mechid, signer, _, end, _ = fields
        window = (genesis, netuid, mechid, signer, end)
        document = _json_record(attempt)
        with self._connection() as connection:
            # Hold the writer lock across the window checks and insert.
            connection.execute("BEGIN IMMEDIATE")
            if connection.execute(
                "SELECT 1 FROM attempts WHERE extrinsic_hash = ?", (extrinsic_hash,)
            ).fetchone():
                raise JournalError(f"signed transaction {extrinsic_hash} is already recorded")
            _check_window_available(connection, window)
            connection.execute("""
                INSERT INTO attempts (
                    extrinsic_hash, genesis_hash, netuid, mechid, validator_hotkey,
                    start_block, end_block, broadcast_head_block, attempt_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (*fields, document))

    def save_receipt(self, tx_hash: str, receipt: dict) -> None:
        document = _json_record(receipt)
        submission = receipt.get("submission", receipt)
        success = (
            isinstance(submission, dict)
            and submission.get("success") is True
            and submission.get("status", receipt.get("status")) in _SUCCESSFUL_RECEIPTS
        )
        with self._connection() as connection:
            updated = connection.execute("""
                UPDATE attempts SET
                    receipt_json = CASE WHEN receipt_success = 1 AND ? = 0
                        THEN receipt_json ELSE ? END,
                    receipt_success = MAX(receipt_success, ?)
                WHERE extrinsic_hash = ?
            """, (int(success), document, int(success), tx_hash))
            if updated.rowcount == 0:
                raise JournalError("submission is absent from the journal")

    def save_readback(self, tx_hash: str, readback: dict) -> None:
        status = readback.get("status") if isinstance(readback, dict) else None
        if not isinstance(status, str) or not status:
            raise JournalError("submission readback requires a status")
        _finalized_height(readback)
        with self._connection() as connection:
            connection.execute("BEGIN IMMEDIATE")
            previous = connection.execute("""
                SELECT readback_json FROM attempts WHERE extrinsic_hash = ?
            """, (tx_hash,)).fetchone()
            if previous is None:
                raise JournalError("submission is absent from the journal")
            if previous[0] is not None:
                try:
                    saved = json.loads(previous[0])
                except ValueError as error:
                    raise JournalError("submission journal contains an invalid readback") from error
                if not isinstance(saved, dict) or not isinstance(saved.get("status"), str):
                    raise JournalError("submission journal contains an invalid readback")
                readback = _merge_readback(saved, readback)
                if readback is saved:
                    return
            connection.execute("""
                UPDATE attempts SET readback_json = ?, readback_status = ?
                WHERE extrinsic_hash = ?
            """, (_json_record(readback), readback["status"], tx_hash))

    def get(self, tx_hash: str) -> dict:
        with self._connection() as connection:
            row = connection.execute("""
                SELECT attempt_json, receipt_json, readback_json FROM attempts
                WHERE extrinsic_hash = ?
            """, (tx_hash,)).fetchone()
        if row is None:
            raise JournalError("submission is absent from the journal")
        try:
            return {
                key: None if value is None else json.loads(value)
                for key, value in zip(("attempt", "receipt", "readback"), row)
            }
        except ValueError as error:
            raise JournalError("submission journal contains an invalid record") from error

    def list_attempts(self, *, netuid: int | None = None, limit: int = 50) -> list[dict]:
        """List recent identifiers and statuses without exposing the planned targets."""
        if type(limit) is not int or not 1 <= limit <= (1 << 63) - 1:
            raise JournalError("submission list limit must be a positive integer")
        if netuid is not None and (type(netuid) is not int or not 1 <= netuid <= 65_535):
            raise JournalError("submission list requires a non-root subnet ID")
        with self._connection() as connection:
            connection.row_factory = sqlite3.Row
            rows = connection.execute("""
                SELECT extrinsic_hash, genesis_hash, netuid, mechid, validator_hotkey,
                    start_block, end_block, broadcast_head_block, receipt_json, readback_status
                FROM attempts WHERE (? IS NULL OR netuid = ?)
                ORDER BY rowid DESC LIMIT ?
            """, (netuid, netuid, limit)).fetchall()
        attempts = []
        for row in rows:
            summary = dict(row)
            saved = summary.pop("receipt_json")
            summary["receipt_status"] = None if saved is None else _receipt_status(saved)
            attempts.append(summary)
        return attempts


def _owner_only_file(metadata: os.stat_result) -> bool:
    return (
        stat.S_ISREG(metadata.st_mode)
        and metadata.st_uid == os.geteuid()
        and not metadata.st_mode & (stat.S_IRWXG | stat.S_IRWXO)
    )


def _check_window_available(connection: sqlite3.Connection, window: tuple[str, int, int, str, int]) -> None:
    newer = connection.execute("""
        SELECT end_block FROM attempts
        WHERE genesis_hash = ? AND netuid = ? AND mechid = ?
          AND validator_hotkey = ? AND end_block > ?
        ORDER BY end_block DESC LIMIT 1
    """, window).fetchone()
    if newer:
        raise JournalError(f"scoring window ends before reserved window {newer[0]}")
    blocked = connection.execute("""
        SELECT extrinsic_hash FROM attempts
        WHERE genesis_hash = ? AND netuid = ? AND mechid = ?
          AND validator_hotkey = ? AND end_block = ?
          AND (receipt_success = 1 OR COALESCE(readback_status, '') NOT IN (?, ?))
        LIMIT 1
    """, (*window, *_RETRYABLE)).fetchone()
    if blocked:
        raise JournalError(f"scoring window is already reserved by {blocked[0]}")


def _check_nonce_available(connection: sqlite3.Connection, genesis_hash: str, hotkey: str) -> None:
    attempts = connection.execute("""
        SELECT extrinsic_hash, netuid, attempt_json, receipt_json, readback_json FROM attempts
        WHERE genesis_hash = ? AND validator_hotkey = ?
    """, (genesis_hash, hotkey))
    for tx_hash, netuid, saved_attempt, saved_receipt, saved_readback in attempts:
        try:
            attempt = json.loads(saved_attempt)
            receipt = {} if saved_receipt is None else json.loads(saved_receipt)
            readback = {} if saved_readback is None else json.loads(saved_readback)
            first = attempt["scan_start_block"]
            last = attempt["broadcast_head_block"] + attempt["transaction_period_blocks"]
            resolved = _has_finalized_receipt_or_rejection(receipt, first, last) or (
                readback.get("inclusion_conflict") is not True
                and _has_finalized_readback(readback, first, last)
            )
        except (ValueError, KeyError, TypeError, AttributeError) as error:
            raise JournalError("submission journal contains an invalid record") from error
        if not resolved:
            raise JournalError(f"reconcile unresolved submission {tx_hash} on subnet {netuid} before signing again")


def _has_finalized_receipt_or_rejection(receipt: dict, first: int, last: int) -> bool:
    submission = receipt.get("submission", receipt)
    status = submission.get("status", receipt.get("status"))
    success = submission.get("success")
    if submission.get("data", {}).get("submission_outcome_unknown"):
        return False
    if status == "submission_failed" and success is False and not submission.get("block_hash"):
        # In the pinned SDK, a failed post-sign result without a block or the
        # unknown-outcome marker means the initial author RPC rejected it.
        return True
    if not (status in _SUCCESSFUL_RECEIPTS and success is True
            or status == "submission_failed" and success is False):
        return False
    height = _extrinsic_height(submission)
    try:
        _chain_hash(submission.get("block_hash"), label="watch receipt block hash")
    except ReportError:
        return False
    return height is not None and first <= height <= last


def _has_finalized_readback(readback: dict, first: int, last: int) -> bool:
    finalized = _finalized_height(readback)
    anchor = _inclusion_anchor(readback)
    if anchor is not None:
        return (
            first <= anchor[0] <= min(last, finalized)
            and _extrinsic_height(readback) == anchor[0]
        )
    return (
        readback.get("status") == "expired_unseen"
        and finalized >= last
        and readback.get("scan_start_block") == first
        and readback.get("scan_end_block") == last
        and readback.get("expiry_upper_bound") == last
    )


def _extrinsic_height(record: dict) -> int | None:
    extrinsic_id = record.get("extrinsic_id")
    if isinstance(extrinsic_id, str):
        match = re.fullmatch(r"([0-9]{1,10})-[0-9]{1,10}", extrinsic_id)
        if match is not None:
            return int(match[1])
    return None


def _json_record(record: dict) -> str:
    if not isinstance(record, dict):
        raise JournalError("submission records must be JSON objects")
    try:
        return json.dumps(record, separators=(",", ":"), allow_nan=False)
    except (TypeError, ValueError, RecursionError) as error:
        raise JournalError("submission record could not be encoded as JSON") from error


def _finalized_height(readback: dict) -> int:
    if "finalized_block" not in readback:
        return -1
    try:
        return _uint(readback["finalized_block"], 32, label="finalized block")
    except ReportError as error:
        raise JournalError("submission readback has an invalid finalized block") from error


def _inclusion_anchor(readback: dict) -> tuple[int, str] | None:
    try:
        return (
            _uint(readback["inclusion_block"], 32, label="inclusion block"),
            _chain_hash(readback["inclusion_block_hash"], label="inclusion block hash"),
        )
    except (KeyError, ReportError):
        return None


def _merge_readback(previous: dict, observed: dict) -> dict:
    prior_status, status = previous["status"], observed["status"]
    prior_height, height = _finalized_height(previous), _finalized_height(observed)
    prior_anchor, anchor = _inclusion_anchor(previous), _inclusion_anchor(observed)
    prior_dispatch, dispatch = _dispatch_outcome(previous), _dispatch_outcome(observed)
    prior_seen = prior_anchor is not None or prior_dispatch is not None
    seen = anchor is not None or dispatch is not None

    if (
        observed.get("inclusion_conflict") is True and anchor is not None
        and observed.get("receipt_block_hash") == anchor[1]
    ):
        # Prefer a complete finalized receipt when an older readback conflicts with it.
        return {**observed, "finalized_block": max(prior_height, height)}

    # Workers may complete out of order, so even a stale result can contradict
    # the saved finalized evidence. Keep the evidence that prevents a retry.
    if (
        (prior_seen and status == "expired_unseen")
        or (prior_dispatch is not None and dispatch is not None and prior_dispatch != dispatch)
        or (prior_anchor is not None and anchor is not None and prior_anchor != anchor)
    ):
        return _flag_conflict(previous, observed)
    if seen and prior_status == "expired_unseen":
        return _flag_conflict(observed, previous)
    if observed.get("inclusion_conflict") is True:
        return _flag_conflict(previous if prior_seen else observed, observed)
    if (
        (status == _INCLUSION_VERIFIED and prior_seen)
        or (status == "inclusion_unconfirmed" and prior_status in _SUCCESSFUL_READBACKS)
    ):
        # An inclusion-only read can add evidence without replacing a completed audit.
        inclusion = dict(observed)
        inclusion.pop("finalized_block", None)
        return _retain_observation(previous, inclusion)
    if previous.get("inclusion_conflict") is True:
        if height >= prior_height and status in _APPLIED and anchor is not None and anchor == prior_anchor:
            return observed
        return _retain_observation(previous, observed)
    if (
        (prior_status in _APPLIED and status not in _APPLIED)
        or (prior_seen and not seen)
        or (prior_dispatch is not None and dispatch is None)
        or (prior_status in _RETRYABLE and status in _INCONCLUSIVE and not seen)
    ):
        return _retain_observation(previous, observed)
    if height < prior_height:
        adds_evidence = (
            (anchor is not None and prior_anchor is None)
            or (dispatch is not None and prior_dispatch is None)
            or (status in _APPLIED and prior_status not in _APPLIED)
        )
        if not adds_evidence:
            return previous
    return _retain_observation(observed, previous)


def _retain_observation(chosen: dict, other: dict) -> dict:
    retained = {}
    prior_anchor, anchor = _inclusion_anchor(chosen), _inclusion_anchor(other)
    if prior_anchor is None and anchor is not None:
        retained["inclusion_block"], retained["inclusion_block_hash"] = anchor
    if (
        anchor is not None and (prior_anchor is None or anchor == prior_anchor)
        and "extrinsic_id" not in chosen and "extrinsic_id" in other
    ):
        retained["extrinsic_id"] = other["extrinsic_id"]
    dispatch = _dispatch_outcome(other)
    if (
        dispatch is not None
        and _dispatch_outcome(chosen) is None
        and (prior_anchor is None or anchor == prior_anchor)
    ):
        retained["dispatch_success"] = dispatch
    height = _finalized_height(other)
    if height > _finalized_height(chosen):
        retained["finalized_block"] = height
    return {**chosen, **retained} if retained else chosen


def _flag_conflict(evidence: dict, conflicting: dict) -> dict:
    result = dict(_retain_observation(evidence, conflicting))
    dispatch = _dispatch_outcome(evidence)
    if dispatch is not None:
        result["dispatch_success"] = dispatch
    result.update(
        status="inclusion_unconfirmed",
        inclusion_conflict=True,
        reason=(conflicting.get("reason") if conflicting.get("inclusion_conflict") is True else None)
        or "conflicting finalized readbacks need review",
        conflicting_readback={
            field: conflicting[field]
            for field in (
                "status", "finalized_block", "inclusion_block", "inclusion_block_hash",
                "dispatch_success", "observed_inclusion_block", "observed_inclusion_block_hash",
                "observed_dispatch_success",
            )
            if field in conflicting
        },
    )
    return result


def _receipt_status(saved: str) -> str | None:
    try:
        receipt = json.loads(saved)
    except ValueError as error:
        raise JournalError("submission journal contains an invalid receipt") from error
    if not isinstance(receipt, dict):
        raise JournalError("submission journal contains an invalid receipt")
    status = receipt.get("status")
    return status if isinstance(status, str) else None


def _attempt_fields(attempt: dict) -> tuple[str, str, int, int, str, int, int, int]:
    try:
        extrinsic_hash = _chain_hash(attempt["extrinsic_hash"], label="transaction hash")
        genesis_hash = _chain_hash(attempt["genesis_hash"], label="genesis hash")
        netuid = _uint(attempt["netuid"], 16, label="subnet ID")
        mechid = _uint(attempt["mechid"], 16, label="mechanism ID")
        signer = _hotkey(attempt["validator_hotkey"])
        start = _uint(attempt["start_block"], 32, label="window start")
        end = _uint(attempt["end_block"], 32, label="window end")
        _chain_hash(attempt["end_block_hash"], label="window end hash")
        _uint(attempt["nonce"], 64, label="transaction nonce")
        digest = attempt["report_digest"]
        scan_start = _uint(attempt["scan_start_block"], 32, label="scan start")
        broadcast_head = _uint(attempt["broadcast_head_block"], 32, label="broadcast head")
        period = _uint(attempt["transaction_period_blocks"], 32, label="transaction period")
        encoded_weights = attempt["encoded_weights"]
        targets = attempt["targets"]
    except (KeyError, TypeError, ReportError) as error:
        raise JournalError("submission attempt is missing valid transaction or window metadata") from error
    if (
        netuid == 0 or end <= start or end > broadcast_head or scan_start > broadcast_head + 1
        or period == 0 or not isinstance(digest, str)
        or re.fullmatch(r"[0-9a-f]{64}", digest) is None
        or not isinstance(encoded_weights, dict) or not encoded_weights
        or not isinstance(targets, list) or not targets
    ):
        raise JournalError("submission attempt has invalid transaction or window metadata")
    return extrinsic_hash, genesis_hash, netuid, mechid, signer, start, end, broadcast_head
