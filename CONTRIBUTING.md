# Contributing

Security fixes, bypass test cases, and false-positive reductions are welcome.

1. Open an issue for behavioral or policy changes.
2. Add tests for every new policy rule or bypass variant.
3. Run `pytest` and `ruff check .`.
4. Run `hermes plugins doctor . --ci` when Hermes is available.
5. Do not include real credentials, private model metadata, or captured tool output.

Policy changes should remain deterministic and must not call an LLM.
