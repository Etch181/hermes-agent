"""Parser for bounded self-healing inspection commands."""
from __future__ import annotations
from typing import Callable


def build_heal_parser(subparsers, *, cmd_heal: Callable) -> None:
    parser = subparsers.add_parser("heal", help="Diagnose, verify, or inspect bounded self-healing incidents")
    parser.add_argument("mode", choices=("diagnose", "verify", "status"), help="diagnose records evidence; verify runs Hermes verification; status reads the incident ledger")
    parser.add_argument("path", nargs="?", default=".", help="Workspace root (default: current directory)")
    parser.add_argument("--failure", default=None, help="Observed failure text for diagnose (required outside status)")
    parser.add_argument("--json", action="store_true", help="Emit JSON")
    parser.set_defaults(func=cmd_heal)
