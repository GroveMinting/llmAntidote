"""Standalone entry point for CI/CD and fleet control-plane commands."""

from __future__ import annotations

import argparse
from collections.abc import Sequence

from .commands import run_cli, setup_cli


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="llm-antidote",
        description="llmAntidote model security and fleet admission CLI",
    )
    setup_cli(parser)
    return run_cli(parser.parse_args(argv))


if __name__ == "__main__":
    raise SystemExit(main())
