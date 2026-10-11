"""Regenerate tests/data/hermes_tool_inventory.json from a Hermes checkout.

Usage (from the repo root, with a Hermes checkout on PYTHONPATH):

    PYTHONPATH=/path/to/hermes-agent python scripts/record_tool_inventory.py \
        --hermes-version "0.21.6+606.b65cd56"

Run this when Hermes adds or renames tools so the inventory test can flag the
classifier drift instead of silently falling through to UNKNOWN.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

_FIXTURE = Path(__file__).resolve().parent.parent / "tests" / "data" / "hermes_tool_inventory.json"
_BRIDGE_TOOLS = ("tool_call", "tool_describe", "tool_search")
_INTENTIONALLY_UNKNOWN = ["tool_call"]


def _collect_names() -> list[str]:
    from model_tools import get_tool_definitions  # type: ignore[import-not-found]

    names: set[str] = set(_BRIDGE_TOOLS)
    for kwargs in ({}, {"quiet_mode": True}):
        try:
            defs = get_tool_definitions(**kwargs) or []
        except TypeError:
            defs = get_tool_definitions() or []
        for entry in defs:
            if not isinstance(entry, dict):
                continue
            function = entry.get("function") if "function" in entry else entry
            name = str((function or {}).get("name") or entry.get("name") or "")
            if name:
                names.add(name)
    return sorted(names)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--hermes-version", required=True)
    parser.add_argument("--output", default=str(_FIXTURE))
    args = parser.parse_args()

    payload = {
        "source": "hermes-agent get_tool_definitions()",
        "hermes_version": args.hermes_version,
        "note": (
            "Stock tool surface plus the deferred tool-search bridge tools. "
            "Regenerate with scripts/record_tool_inventory.py against a pinned Hermes checkout."
        ),
        "tools": _collect_names(),
        "intentionally_unknown": _INTENTIONALLY_UNKNOWN,
    }
    Path(args.output).write_text(json.dumps(payload, indent=2) + "\n")
    print(f"wrote {len(payload['tools'])} tools to {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
