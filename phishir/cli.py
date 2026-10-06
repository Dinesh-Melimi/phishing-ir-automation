"""Command-line interface: `phishir analyze samples/*.eml -o cases/`."""

from __future__ import annotations

import argparse
import logging
import sys

from . import __version__
from .enrichment import build_providers
from .pipeline import analyze_file, write_outputs
from .webhook import post_webhook


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="phishir", description="SOAR-lite phishing IR pipeline")
    ap.add_argument("--version", action="version", version=__version__)
    sub = ap.add_subparsers(dest="cmd", required=True)
    a = sub.add_parser("analyze", help="analyze one or more .eml files")
    a.add_argument("files", nargs="+")
    a.add_argument("-o", "--out", default="cases", help="output directory (default: cases/)")
    a.add_argument("--live", action="store_true", help="use real intel providers (needs API keys)")
    a.add_argument("--webhook", action="store_true", help="post summary to PHISHIR_WEBHOOK_URL")
    a.add_argument("--fail-on", choices=["low", "medium", "high", "critical"],
                   help="exit 2 if any case reaches this severity (for automation)")
    a.add_argument("-v", "--verbose", action="store_true")
    args = ap.parse_args(argv)

    logging.basicConfig(level=logging.INFO if args.verbose else logging.WARNING,
                        format="%(levelname)s %(name)s: %(message)s")
    providers = build_providers(live=args.live or None)
    order = ["low", "medium", "high", "critical"]
    worst = "low"
    for f in args.files:
        case = analyze_file(f, providers)
        _, m = write_outputs(case, args.out)
        if args.webhook:
            post_webhook(case)
        worst = max(worst, case.severity, key=order.index)
        print(f"{case.case_id}  {case.severity.upper():8} {case.score:3}/100  {f}  -> {m}")
    if args.fail_on and order.index(worst) >= order.index(args.fail_on):
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
