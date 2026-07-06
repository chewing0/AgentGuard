from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from .agents import DemoAgent
from .audit import AuditLogger, read_audit, summarize_events
from .attacks import builtin_attack_scenarios
from .benchmarks import load_tasks
from .evaluation import run_evaluation
from .gateway import SecurityGateway
from .registry import ToolRegistry
from .schemas import SecurityContext, ToolCall
from .tools import attach_builtin_handlers
from .ui import build_dashboard


PROJECT_ROOT = Path.cwd()
DEFAULT_TASKS = PROJECT_ROOT / "data" / "benchmark_tasks.jsonl"
DEFAULT_TOOLS = PROJECT_ROOT / "data" / "tools.json"
DEFAULT_RUNS = PROJECT_ROOT / "runs"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="agentguard", description="Agent tool-call security evaluation and gateway demo.")
    sub = parser.add_subparsers(dest="command", required=True)

    evaluate = sub.add_parser("evaluate", help="Run the benchmark across protection modes.")
    evaluate.add_argument("--tasks", default=str(DEFAULT_TASKS))
    evaluate.add_argument("--tools", default=str(DEFAULT_TOOLS))
    evaluate.add_argument("--output", default=str(DEFAULT_RUNS / "latest"))
    evaluate.add_argument("--modes", default="none,prompt_only,rule_guard,gateway")
    evaluate.add_argument("--execute", action="store_true", help="Execute allowed demo tools while evaluating.")

    demo = sub.add_parser("demo", help="Run the gateway on one benchmark task or one raw call.")
    demo.add_argument("--task", help="Benchmark task id to replay through the gateway.")
    demo.add_argument("--call-json", help="Raw JSON object with tool_name and params.")
    demo.add_argument("--context-json", help="Raw JSON security context.")
    demo.add_argument("--tasks", default=str(DEFAULT_TASKS))
    demo.add_argument("--tools", default=str(DEFAULT_TOOLS))
    demo.add_argument("--audit", default=str(DEFAULT_RUNS / "demo_audit.jsonl"))
    demo.add_argument("--confirmed", action="store_true", help="Override context.confirmed for demo replay.")

    inspect = sub.add_parser("inspect-audit", help="Summarize a JSONL audit file.")
    inspect.add_argument("path")

    list_tools = sub.add_parser("list-tools", help="List registered tool security policies.")
    list_tools.add_argument("--tools", default=str(DEFAULT_TOOLS))

    validate = sub.add_parser("validate-benchmark", help="Check expected gateway decisions in the benchmark labels.")
    validate.add_argument("--tasks", default=str(DEFAULT_TASKS))
    validate.add_argument("--tools", default=str(DEFAULT_TOOLS))

    agent = sub.add_parser("agent", help="Run the deterministic demo agent on a natural-language task.")
    agent.add_argument("task", nargs="?", default="Generate a security assessment report for AgentGuard.")
    agent.add_argument("--tools", default=str(DEFAULT_TOOLS))
    agent.add_argument("--audit", default=str(DEFAULT_RUNS / "agent_audit.jsonl"))
    agent.add_argument("--report-path", default="data/demo_workspace/scratch/agent_report.md")
    agent.add_argument("--untrusted", action="store_true", help="Treat retrieved task context as untrusted.")
    agent.add_argument("--simulate-attack", action="store_true", help="Simulate following a poisoned KB instruction.")

    attacks = sub.add_parser("list-attacks", help="List built-in attack scenarios.")
    attacks.add_argument("--json", action="store_true", help="Print machine-readable scenario JSON.")

    confirm = sub.add_parser("confirm-demo", help="Run a high-risk call through the confirmation flow.")
    confirm.add_argument("--call-json", help="Raw JSON object with tool_name and params.")
    confirm.add_argument("--context-json", help="Raw JSON security context.")
    confirm.add_argument("--tools", default=str(DEFAULT_TOOLS))
    confirm.add_argument("--audit", default=str(DEFAULT_RUNS / "confirm_audit.jsonl"))
    confirm_choice = confirm.add_mutually_exclusive_group(required=True)
    confirm_choice.add_argument("--approve", action="store_true", help="Approve and re-execute with confirmation.")
    confirm_choice.add_argument("--deny", action="store_true", help="Deny the requested high-risk call.")

    dashboard = sub.add_parser("dashboard", help="Generate a static HTML dashboard from an evaluation run.")
    dashboard.add_argument("--run", default=str(DEFAULT_RUNS / "latest"))
    dashboard.add_argument("--output", help="Output HTML path. Defaults to <run>/dashboard.html.")

    args = parser.parse_args(argv)
    if args.command == "evaluate":
        return _cmd_evaluate(args)
    if args.command == "demo":
        return _cmd_demo(args)
    if args.command == "inspect-audit":
        return _cmd_inspect(args)
    if args.command == "list-tools":
        return _cmd_list_tools(args)
    if args.command == "validate-benchmark":
        return _cmd_validate(args)
    if args.command == "agent":
        return _cmd_agent(args)
    if args.command == "list-attacks":
        return _cmd_list_attacks(args)
    if args.command == "confirm-demo":
        return _cmd_confirm_demo(args)
    if args.command == "dashboard":
        return _cmd_dashboard(args)
    parser.error(f"Unknown command: {args.command}")
    return 2


def _cmd_evaluate(args: argparse.Namespace) -> int:
    modes = [mode.strip() for mode in args.modes.split(",") if mode.strip()]
    result = run_evaluation(
        tasks_path=args.tasks,
        tools_path=args.tools,
        workspace_root=PROJECT_ROOT,
        output_dir=args.output,
        modes=modes,
        execute_allowed=args.execute,
    )
    print(result.markdown())
    print()
    print(f"Wrote metrics to {Path(args.output) / 'metrics.json'}")
    print(f"Wrote report to {Path(args.output) / 'report.md'}")
    return 0


def _cmd_demo(args: argparse.Namespace) -> int:
    registry = attach_builtin_handlers(ToolRegistry.from_json(args.tools), PROJECT_ROOT)
    gateway = SecurityGateway(registry, PROJECT_ROOT, AuditLogger(args.audit))
    if args.task:
        tasks = {task.task_id: task for task in load_tasks(args.tasks)}
        if args.task not in tasks:
            print(f"Task not found: {args.task}", file=sys.stderr)
            return 1
        task = tasks[args.task]
        context = _maybe_confirm(task.context, args.confirmed)
        for step in task.steps:
            decision, result = gateway.execute(step.call, context, labels=step.labels() | {"category": task.category})
            _print_demo_result(step.step_id, step.call.tool_name, decision.to_dict(), result.to_dict() if result else None)
        print(f"Audit written to {args.audit}")
        return 0

    if not args.call_json:
        print("Provide either --task or --call-json", file=sys.stderr)
        return 2
    call = ToolCall.from_dict(json.loads(args.call_json))
    context_raw: dict[str, Any] = json.loads(args.context_json) if args.context_json else {}
    context = _maybe_confirm(SecurityContext.from_dict(context_raw), args.confirmed)
    decision, result = gateway.execute(call, context)
    _print_demo_result(call.step_id, call.tool_name, decision.to_dict(), result.to_dict() if result else None)
    print(f"Audit written to {args.audit}")
    return 0


def _cmd_inspect(args: argparse.Namespace) -> int:
    summary = summarize_events(read_audit(args.path))
    print(json.dumps(summary.to_dict(), indent=2, ensure_ascii=False))
    return 0


def _cmd_list_tools(args: argparse.Namespace) -> int:
    registry = ToolRegistry.from_json(args.tools)
    for name in registry.names():
        spec = registry.require(name)
        print(f"{name}: operation={spec.operation.value}, risk={spec.risk_level.name.lower()}, scopes={sorted(spec.required_scopes)}")
    return 0


def _cmd_validate(args: argparse.Namespace) -> int:
    registry = attach_builtin_handlers(ToolRegistry.from_json(args.tools), PROJECT_ROOT)
    gateway = SecurityGateway(registry, PROJECT_ROOT)
    mismatches: list[dict[str, str]] = []
    for task in load_tasks(args.tasks):
        for step in task.steps:
            expected = step.expected_gateway_decision
            if not expected:
                continue
            actual = gateway.inspect(step.call, task.context).decision.value
            if actual != expected:
                mismatches.append({"task_id": task.task_id, "step_id": step.step_id, "expected": expected, "actual": actual})
    if mismatches:
        print(json.dumps({"mismatches": mismatches}, indent=2, ensure_ascii=False))
        return 1
    print("Benchmark labels match gateway decisions.")
    return 0


def _cmd_agent(args: argparse.Namespace) -> int:
    registry = attach_builtin_handlers(ToolRegistry.from_json(args.tools), PROJECT_ROOT)
    gateway = SecurityGateway(registry, PROJECT_ROOT, AuditLogger(args.audit))
    context = SecurityContext(
        user_id="demo-agent",
        role="analyst",
        scopes={"file:read", "file:write", "db:read", "kb:read", "search:read", "network:api"},
        trusted_input=not (args.untrusted or args.simulate_attack),
    )
    run = DemoAgent(gateway, report_path=args.report_path).run(
        args.task,
        context=context,
        simulate_attack_followup=args.simulate_attack,
    )
    print(run.markdown())
    print(f"Audit written to {args.audit}")
    return 0


def _cmd_list_attacks(args: argparse.Namespace) -> int:
    scenarios = builtin_attack_scenarios()
    if args.json:
        print(json.dumps([scenario.to_dict() for scenario in scenarios], indent=2, ensure_ascii=False))
        return 0
    for scenario in scenarios:
        violations = ", ".join(scenario.expected_violation_types)
        print(f"{scenario.scenario_id}: {scenario.category} [{violations}]")
        print(f"  {scenario.description}")
    return 0


def _cmd_confirm_demo(args: argparse.Namespace) -> int:
    registry = attach_builtin_handlers(ToolRegistry.from_json(args.tools), PROJECT_ROOT)
    gateway = SecurityGateway(registry, PROJECT_ROOT, AuditLogger(args.audit))
    if args.call_json:
        call = ToolCall.from_dict(json.loads(args.call_json))
    else:
        call = ToolCall(
            tool_name="code.python",
            params={"code": "sum([1, 2, 3])"},
            task_id="confirm-demo",
            step_id="confirm-s1",
            declared_purpose="Evaluate a simple arithmetic expression after human confirmation.",
        )
    if args.context_json:
        context = SecurityContext.from_dict(json.loads(args.context_json))
    else:
        context = SecurityContext(user_id="u-researcher", role="researcher", scopes={"code:execute"}, confirmed=False)
    decision, result = gateway.resolve_confirmation(
        call,
        context,
        approve=args.approve,
        labels={"mode": "confirm_demo"},
    )
    _print_demo_result(call.step_id, call.tool_name, decision.to_dict(), result.to_dict() if result else None)
    print(f"Audit written to {args.audit}")
    return 0


def _cmd_dashboard(args: argparse.Namespace) -> int:
    output = build_dashboard(args.run, args.output)
    print(f"Dashboard written to {output}")
    return 0


def _maybe_confirm(context: SecurityContext, confirmed: bool) -> SecurityContext:
    if not confirmed:
        return context
    return SecurityContext(
        user_id=context.user_id,
        role=context.role,
        scopes=set(context.scopes),
        confirmed=True,
        session_id=context.session_id,
        trusted_input=context.trusted_input,
    )


def _print_demo_result(step_id: str, tool_name: str, decision: dict[str, Any], result: dict[str, Any] | None) -> None:
    print(f"[{step_id}] {tool_name}: {decision['decision']} ({decision['risk_level']}) - {decision['reason']}")
    if decision.get("signals"):
        for signal in decision["signals"]:
            print(f"  signal={signal['signal_type']} level={signal['level']} evidence={signal.get('evidence')}")
    if result:
        print("  result=" + json.dumps(result, ensure_ascii=False))


if __name__ == "__main__":
    raise SystemExit(main())
