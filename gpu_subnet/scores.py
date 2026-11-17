"""Capture scores API responses for later signature verification."""

import argparse
import json
import os
import re
import sys
from pathlib import Path

from .bob_scores import DEFAULT_WINDOW_SECONDS, fetch_bob_scores
from .scores_capture import load_capture, save_capture
from .scores_http import fetch_scores


def _request_headers(specifications: list[str]) -> dict[str, str]:
    headers = {}
    for specification in specifications:
        name, separator, variable = specification.partition("=")
        if not separator or not name or not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", variable):
            raise ValueError("--header-env requires HEADER=ENV_VAR")
        name = name.lower()
        if name in headers:
            raise ValueError("duplicate --header-env header")
        value = os.environ.get(variable)
        if not value:
            raise ValueError(f"environment variable {variable} is missing or empty")
        headers[name] = value
    return headers


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Capture or inspect a raw scores response.")
    commands = parser.add_subparsers(dest="command", required=True)

    capture = commands.add_parser("capture", help="fetch and save one response over HTTPS")
    endpoint = capture.add_mutually_exclusive_group(required=True)
    endpoint.add_argument("--url", help="full scores API URL with query parameters")
    endpoint.add_argument("--api-base", help="Bob Labs HTTPS origin; uses SCORES_TOKEN")
    capture.add_argument("--netuid", type=int, help="Bittensor subnet for the Bob Labs report")
    capture.add_argument("--window-seconds", type=int, help="Bob Labs window (default 86400)")
    capture.add_argument("--output", type=Path, required=True, help="new capture file")
    capture.add_argument("--header-env", action="append", default=[], metavar="HEADER=ENV_VAR")
    capture.add_argument("--timeout", type=float, default=30.0, help="socket timeout in seconds")

    inspect = commands.add_parser("inspect", help="read capture metadata offline")
    inspect.add_argument("--input", type=Path, required=True, help="saved capture file")
    args = parser.parse_args(argv)

    try:
        if args.command == "capture":
            if os.path.lexists(args.output):
                raise ValueError("output capture already exists")
            if not args.output.parent.is_dir():
                raise ValueError("output directory must exist")
            if args.api_base is not None:
                if args.netuid is None or args.header_env:
                    raise ValueError("--api-base requires --netuid and takes SCORES_TOKEN from the environment")
                response = fetch_bob_scores(
                    args.api_base, os.environ.get("SCORES_TOKEN", ""), netuid=args.netuid,
                    window_seconds=(
                        DEFAULT_WINDOW_SECONDS if args.window_seconds is None else args.window_seconds
                    ),
                    timeout=args.timeout,
                )
            else:
                if args.netuid is not None or args.window_seconds is not None:
                    raise ValueError("--netuid and --window-seconds require --api-base")
                headers = _request_headers(args.header_env)
                response = fetch_scores(args.url, headers=headers or None, timeout=args.timeout)
            save_capture(args.output, response)
        else:
            response = load_capture(args.input)
    except (OSError, ValueError) as error:
        print(f"Scores command failed: {error}", file=sys.stderr)
        return 2

    receipt = {
        "status": "unverified_capture",
        "http_status": response.status,
        "body_bytes": len(response.body),
        "body_sha256": response.body_sha256,
        "headers": [name for name, _ in response.headers],
    }
    if response.trailers:
        receipt["trailers"] = [name for name, _ in response.trailers]
    print(json.dumps(receipt, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
