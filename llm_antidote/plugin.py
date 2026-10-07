"""Hermes registration and lifecycle hooks."""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

from .audit import MetadataAudit
from .commands import run_cli, setup_cli
from .policy import PolicyConfig, PolicyDecision, PolicyEngine
from .runtime import RuntimeRoutes
from .state import SessionRiskStore


def _positive_int(value: Any, default: int, maximum: int) -> int:
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        return default
    return max(1, min(parsed, maximum))


def _tool_succeeded(status: Any, error_type: Any, result: Any) -> bool:
    if error_type:
        return False
    clean = str(status or "success").lower()
    if clean in {"blocked", "denied", "error", "failed", "timeout"}:
        return False
    if isinstance(result, str):
        try:
            parsed = json.loads(result)
        except (TypeError, ValueError):
            return True
        if isinstance(parsed, dict):
            error = parsed.get("error")
            if error is not None and error != "" and error is not False:
                return False
    return True


@dataclass
class AntidoteRuntime:
    mode: str
    engine: PolicyEngine
    risks: SessionRiskStore
    audit: MetadataAudit
    routes: RuntimeRoutes

    def session_keys(self, session_id: str = "", task_id: str = "") -> tuple[str, ...]:
        keys = tuple(dict.fromkeys(value for value in (session_id, task_id) if value))
        return keys or ("unknown",)

    def decide(
        self,
        *,
        tool_name: str,
        args: Any,
        session_id: str = "",
        task_id: str = "",
    ) -> PolicyDecision:
        keys = self.session_keys(session_id, task_id)
        self.risks.link(keys)
        decision = self.engine.assess(
            tool_name,
            args,
            session_tainted=any(self.risks.is_tainted(key) for key in keys),
        )
        if decision.would_action != "allow":
            self.audit.record(
                action=decision.action,
                would_action=decision.would_action,
                tool_name=tool_name,
                rule_ids=decision.rule_ids,
                session_key=keys[0],
            )
        return decision

    def post_tool(
        self,
        *,
        tool_name: str,
        args: Any,
        result: Any = None,
        status: Any = None,
        error_type: Any = None,
        session_id: str = "",
        task_id: str = "",
    ) -> None:
        if not _tool_succeeded(status, error_type, result):
            return
        decision = self.engine.assess(tool_name, args, session_tainted=False)
        if decision.sensitive:
            self.risks.mark_many(self.session_keys(session_id, task_id), decision.sensitive)

    def status(self) -> dict[str, object]:
        return {
            "mode": self.mode,
            "risk": self.risks.summary(),
            "audit": self.audit.summary(),
            "runtime_route": self.routes.snapshot(),
        }

    def status_text(self) -> str:
        status = self.status()
        risk = status["risk"]
        audit = status["audit"]
        route = status["runtime_route"]
        assert isinstance(risk, dict) and isinstance(audit, dict) and isinstance(route, dict)
        categories = ", ".join(risk.get("categories", [])) or "none"
        model = route.get("model") or "not observed"
        provider = route.get("provider") or "not observed"
        return (
            "llmAntidote status\n"
            f"- mode: {self.mode}\n"
            f"- tainted sessions: {risk.get('tainted_sessions', 0)}\n"
            f"- taint categories: {categories}\n"
            f"- retained audit events: {audit.get('retained_events', 0)}\n"
            f"- latest model route: {provider} / {model}"
        )


def build_runtime(ctx: Any) -> AntidoteRuntime:
    mode = PolicyConfig.from_value(ctx.get_config("mode", "balanced")).mode
    ttl = _positive_int(ctx.get_config("taint_ttl_minutes", 60), 60, 24 * 60)
    capacity = _positive_int(ctx.get_config("audit_capacity", 200), 200, 10_000)
    return AntidoteRuntime(
        mode=mode,
        engine=PolicyEngine(PolicyConfig(mode)),
        risks=SessionRiskStore(ttl),
        audit=MetadataAudit(capacity),
        routes=RuntimeRoutes(),
    )


def register(ctx: Any) -> None:
    runtime = build_runtime(ctx)

    def pre_tool_call(
        tool_name: str = "",
        args: Any = None,
        session_id: str = "",
        task_id: str = "",
        **_: Any,
    ) -> dict[str, str] | None:
        decision = runtime.decide(
            tool_name=tool_name,
            args=args,
            session_id=session_id,
            task_id=task_id,
        )
        if decision.action == "block":
            return {"action": "block", "message": decision.message}
        if decision.action == "approve":
            rule = decision.rule_ids[0] if decision.rule_ids else "policy"
            return {
                "action": "approve",
                "message": decision.message,
                "rule_key": f"llm-antidote:{rule}",
            }
        return None

    def post_tool_call(
        tool_name: str = "",
        args: Any = None,
        result: Any = None,
        status: Any = None,
        error_type: Any = None,
        session_id: str = "",
        task_id: str = "",
        **_: Any,
    ) -> None:
        runtime.post_tool(
            tool_name=tool_name,
            args=args,
            result=result,
            status=status,
            error_type=error_type,
            session_id=session_id,
            task_id=task_id,
        )

    def pre_api_request(
        provider: Any = "",
        model: Any = "",
        base_url: Any = "",
        **_: Any,
    ) -> None:
        runtime.routes.observe(provider=provider, model=model, base_url=base_url)

    def on_session_start(session_id: str = "", **_: Any) -> None:
        runtime.risks.clear(session_id)

    def on_session_reset(
        session_id: str = "",
        old_session_id: str = "",
        new_session_id: str = "",
        **_: Any,
    ) -> None:
        runtime.risks.clear(session_id, old_session_id, new_session_id)

    def on_session_finalize(session_id: str = "", **_: Any) -> None:
        runtime.risks.clear(session_id)

    def slash_command(raw_args: str) -> str:
        command = (raw_args or "status").strip().lower()
        if command in {"", "status"}:
            return runtime.status_text()
        if command == "clear":
            runtime.risks.clear_all()
            return "llmAntidote cleared all in-process session taint metadata."
        return "Usage: /antidote [status|clear]"

    ctx.register_hook("pre_tool_call", pre_tool_call)
    ctx.register_hook("post_tool_call", post_tool_call)
    ctx.register_hook("pre_api_request", pre_api_request)
    ctx.register_hook("on_session_start", on_session_start)
    ctx.register_hook("on_session_reset", on_session_reset)
    ctx.register_hook("on_session_finalize", on_session_finalize)
    ctx.register_command(
        "antidote",
        slash_command,
        description="Show or clear llmAntidote runtime risk metadata",
        args_hint="[status|clear]",
    )
    ctx.register_cli_command(
        "antidote",
        "Inspect models and run llmAntidote behavioral evaluations",
        setup_cli,
        lambda args: run_cli(args, runtime=runtime),
        description="Runtime guardrails, model provenance, and behavioral evaluation",
    )
