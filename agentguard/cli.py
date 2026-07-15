from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from .agents import (
    DemoAgent,
    LangGraphAutonomousAgent,
    SecurityOperationsAgent,
    build_scripted_security_ops_model,
    load_chat_model,
)
from .audit import AuditLogger, read_audit, summarize_events
from .attacks import builtin_attack_scenarios
from .benchmarks import load_tasks
from .autonomous_evaluation import run_autonomous_benchmark
from .detectors import SensitiveDataDetector
from .evaluation import run_evaluation
from .gateway import SecurityGateway
from .model_config import load_chat_model_from_config
from .registry import ToolRegistry
from .schemas import SecurityContext, ToolCall
from .tools import attach_builtin_handlers
from .ui import build_dashboard


SOURCE_ROOT = Path(__file__).resolve().parents[1]
# Editable/source installs can locate the repository directly. A regular wheel
# does not bundle top-level fixtures, so fall back to the caller's repository.
PROJECT_ROOT = SOURCE_ROOT if (SOURCE_ROOT / "data" / "tools.json").is_file() else Path.cwd().resolve()
DEFAULT_BENCHMARKS = PROJECT_ROOT / "data" / "benchmarks"
DEFAULT_TASKS = DEFAULT_BENCHMARKS / "benchmark_tasks.jsonl"
DEFAULT_AUTONOMOUS_TASKS = DEFAULT_BENCHMARKS / "autonomous_benchmark_tasks.jsonl"
DEFAULT_TOOLS = PROJECT_ROOT / "data" / "tools.json"
DEFAULT_RUNS = PROJECT_ROOT / "runs"
DEFAULT_MANUAL_RUNS = DEFAULT_RUNS / "manual"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="agentguard", description="Agent tool-call security evaluation and gateway demo.")
    sub = parser.add_subparsers(dest="command", required=True)

    evaluate = sub.add_parser("evaluate", help="Run the benchmark across protection modes.")
    evaluate.add_argument("--tasks", default=str(DEFAULT_TASKS))
    evaluate.add_argument("--tools", default=str(DEFAULT_TOOLS))
    evaluate.add_argument("--output", default=str(DEFAULT_MANUAL_RUNS / "evaluation"))
    evaluate.add_argument("--modes", default="none,prompt_only,rule_guard,gateway")
    evaluate.add_argument("--execute", action="store_true", help="Execute allowed demo tools while evaluating.")
    evaluate.add_argument("--overwrite", action="store_true", help="Replace generated artifacts in the output directory.")

    demo = sub.add_parser("demo", help="Run the gateway on one benchmark task or one raw call.")
    demo.add_argument("--task", help="Benchmark task id to replay through the gateway.")
    demo.add_argument("--call-json", help="Raw JSON object with tool_name and params.")
    demo.add_argument("--context-json", help="Raw JSON security context.")
    demo.add_argument("--tasks", default=str(DEFAULT_TASKS))
    demo.add_argument("--tools", default=str(DEFAULT_TOOLS))
    demo.add_argument("--audit", default=str(DEFAULT_MANUAL_RUNS / "demo_audit.jsonl"))
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
    agent.add_argument("--audit", default=str(DEFAULT_MANUAL_RUNS / "demo_agent_audit.jsonl"))
    agent.add_argument("--report-path", default="runs/manual/reports/demo_agent_report.md")
    agent.add_argument("--untrusted", action="store_true", help="Treat retrieved task context as untrusted.")
    agent.add_argument("--simulate-attack", action="store_true", help="Simulate following a poisoned KB instruction.")

    soc_agent = sub.add_parser("security-agent", help="Run the SOC security-operations agent on an alert triage task.")
    soc_agent.add_argument("task", nargs="?", default="Triage alert SOC-104 and produce a containment recommendation.")
    soc_agent.add_argument("--tools", default=str(DEFAULT_TOOLS))
    soc_agent.add_argument("--audit", default=str(DEFAULT_MANUAL_RUNS / "security_agent_audit.jsonl"))
    soc_agent.add_argument("--report-path")
    soc_agent.add_argument("--untrusted", action="store_true", help="Treat retrieved task context as untrusted.")
    soc_agent.add_argument("--simulate-attack", action="store_true", help="Simulate a vulnerable follow-up from poisoned KB content.")

    langgraph_demo = sub.add_parser("langgraph-demo", help="Run a LangGraph tool-node adapter demo through the gateway.")
    langgraph_demo.add_argument("--tool", default="kb.search", help="Registered AgentGuard tool to call.")
    langgraph_demo.add_argument(
        "--params-json",
        default='{"query":"gateway report recommendations","top_k":2}',
        help="JSON object passed as the LangGraph tool-call arguments.",
    )
    langgraph_demo.add_argument("--tools", default=str(DEFAULT_TOOLS))
    langgraph_demo.add_argument("--audit", default=str(DEFAULT_MANUAL_RUNS / "langgraph_audit.jsonl"))
    langgraph_demo.add_argument("--untrusted", action="store_true", help="Treat tool-call source content as untrusted.")

    autonomous = sub.add_parser("autonomous-agent", help="Run a full LangGraph autonomous LLM agent behind AgentGuard.")
    autonomous.add_argument("task", nargs="?", default="Triage SOC-104 using vendor advisory guidance and write a report.")
    autonomous.add_argument("--tools", default=str(DEFAULT_TOOLS))
    autonomous.add_argument("--audit", default=str(DEFAULT_MANUAL_RUNS / "autonomous_agent_audit.jsonl"))
    autonomous.add_argument("--report-path", default="runs/manual/reports/langgraph_SOC-104_triage.md")
    autonomous.add_argument(
        "--workspace-root",
        default=str(PROJECT_ROOT),
        help="Workspace exposed to tools. Use an isolated directory for black-box tests.",
    )
    autonomous_model = autonomous.add_mutually_exclusive_group()
    autonomous_model.add_argument("--model", help="Real LangChain chat model name, for example openai:gpt-4.1-mini.")
    autonomous_model.add_argument("--model-config", help="JSON config for an OpenAI-compatible model.")
    autonomous.add_argument("--simulate-attack", action="store_true", help="Script the LLM to follow poisoned retrieved content.")
    autonomous.add_argument("--untrusted", action="store_true", help="Treat task and retrieved context as untrusted.")
    autonomous.add_argument("--recursion-limit", type=int, default=20)
    autonomous.add_argument(
        "--enable-fixture-tool",
        action="append",
        default=[],
        dest="enabled_fixture_tools",
        help=(
            "Explicitly expose one benchmark_fixture tool to the model. "
            "Repeat the flag to enable multiple isolated research fixtures."
        ),
    )

    autonomous_benchmark = sub.add_parser("autonomous-benchmark", help="Run full autonomous-agent attack benchmark tasks.")
    autonomous_benchmark.add_argument("--tasks", default=str(DEFAULT_AUTONOMOUS_TASKS))
    autonomous_benchmark.add_argument("--tools", default=str(DEFAULT_TOOLS))
    autonomous_benchmark.add_argument("--output", default=str(DEFAULT_MANUAL_RUNS / "autonomous"))
    autonomous_benchmark_model = autonomous_benchmark.add_mutually_exclusive_group()
    autonomous_benchmark_model.add_argument("--model", help="Real LangChain chat model name, for example openai:gpt-4.1-mini.")
    autonomous_benchmark_model.add_argument("--model-config", help="JSON config for an OpenAI-compatible model.")
    autonomous_benchmark.add_argument("--recursion-limit", type=int, default=20)
    autonomous_benchmark.add_argument("--overwrite", action="store_true", help="Replace generated artifacts in the output directory.")

    attacks = sub.add_parser("list-attacks", help="List built-in attack scenarios.")
    attacks.add_argument("--json", action="store_true", help="Print machine-readable scenario JSON.")

    confirm = sub.add_parser("confirm-demo", help="Run a high-risk call through the confirmation flow.")
    confirm.add_argument("--call-json", help="Raw JSON object with tool_name and params.")
    confirm.add_argument("--context-json", help="Raw JSON security context.")
    confirm.add_argument("--tools", default=str(DEFAULT_TOOLS))
    confirm.add_argument("--audit", default=str(DEFAULT_MANUAL_RUNS / "confirm_audit.jsonl"))
    confirm_choice = confirm.add_mutually_exclusive_group(required=True)
    confirm_choice.add_argument("--approve", action="store_true", help="Approve and re-execute with confirmation.")
    confirm_choice.add_argument("--deny", action="store_true", help="Deny the requested high-risk call.")

    dashboard = sub.add_parser("dashboard", help="Generate a static HTML dashboard from an evaluation run.")
    dashboard.add_argument("--run", default=str(DEFAULT_MANUAL_RUNS / "evaluation"))
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
    if args.command == "security-agent":
        return _cmd_security_agent(args)
    if args.command == "langgraph-demo":
        return _cmd_langgraph_demo(args)
    if args.command == "autonomous-agent":
        return _cmd_autonomous_agent(args)
    if args.command == "autonomous-benchmark":
        return _cmd_autonomous_benchmark(args)
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
        overwrite=args.overwrite,
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


def _cmd_security_agent(args: argparse.Namespace) -> int:
    registry = attach_builtin_handlers(ToolRegistry.from_json(args.tools), PROJECT_ROOT)
    gateway = SecurityGateway(registry, PROJECT_ROOT, AuditLogger(args.audit))
    context = SecurityContext(
        user_id="soc-analyst",
        role="analyst",
        scopes={"file:read", "file:write", "db:read", "kb:read", "threat:intel"},
        trusted_input=not (args.untrusted or args.simulate_attack),
    )
    run = SecurityOperationsAgent(gateway, report_path=args.report_path).run(
        args.task,
        context=context,
        simulate_vulnerable_followup=args.simulate_attack,
    )
    print(run.markdown())
    print(f"Audit written to {args.audit}")
    return 0


def _cmd_langgraph_demo(args: argparse.Namespace) -> int:
    try:
        from langchain_core.messages import AIMessage
        from langgraph.graph import END, START, MessagesState, StateGraph
    except ImportError as exc:
        print(
            "LangGraph demo dependencies are not installed. "
            "Install with: python -m pip install -e .[langgraph]",
            file=sys.stderr,
        )
        print(f"Missing dependency detail: {exc}", file=sys.stderr)
        return 1

    from .adapters import LangGraphGatewayAdapter

    try:
        params = json.loads(args.params_json)
    except json.JSONDecodeError as exc:
        print(f"--params-json is not valid JSON: {exc}", file=sys.stderr)
        return 2
    if not isinstance(params, dict):
        print("--params-json must be a JSON object", file=sys.stderr)
        return 2

    registry = attach_builtin_handlers(ToolRegistry.from_json(args.tools), PROJECT_ROOT)
    if not registry.get(args.tool):
        print(f"Tool not found: {args.tool}", file=sys.stderr)
        return 2
    gateway = SecurityGateway(registry, PROJECT_ROOT, AuditLogger(args.audit))
    context = SecurityContext(
        user_id="langgraph-demo",
        role="analyst",
        scopes={"file:read", "file:write", "db:read", "kb:read", "search:read", "network:api", "threat:intel"},
        trusted_input=not args.untrusted,
    )
    adapter = LangGraphGatewayAdapter(gateway, context, task_id="langgraph-demo")
    framework_tool = adapter.to_framework_tool_name(args.tool)

    builder = StateGraph(MessagesState)
    builder.add_node("tools", adapter.tool_node)
    builder.add_edge(START, "tools")
    builder.add_edge("tools", END)
    graph = builder.compile()
    result = graph.invoke(
        {
            "messages": [
                AIMessage(
                    content="",
                    tool_calls=[{"name": framework_tool, "args": params, "id": "call-agentguard-demo"}],
                )
            ]
        }
    )
    final_message = result["messages"][-1]
    print(f"LangGraph adapter executed {args.tool} as {framework_tool}")
    print(final_message.content)
    print(f"Audit written to {args.audit}")
    return 0


def _cmd_autonomous_agent(args: argparse.Namespace) -> int:
    workspace_root = Path(args.workspace_root).resolve()
    registry = attach_builtin_handlers(ToolRegistry.from_json(args.tools), workspace_root)
    gateway = SecurityGateway(
        registry,
        workspace_root,
        AuditLogger(args.audit, workspace_root=workspace_root),
    )
    context = SecurityContext(
        user_id="langgraph-autonomous-agent",
        role="analyst",
        scopes={"file:read", "file:write", "db:read", "kb:read", "search:read", "network:api", "threat:intel"},
        trusted_input=not (args.untrusted or args.simulate_attack),
    )
    try:
        tool_names = _tool_names_for_explicit_fixtures(
            registry,
            args.enabled_fixture_tools,
        )
        if args.model_config:
            model = load_chat_model_from_config(args.model_config)
        elif args.model:
            model = load_chat_model(args.model)
        else:
            model = build_scripted_security_ops_model(
                report_path=args.report_path,
                simulate_attack=args.simulate_attack,
            )
        agent = LangGraphAutonomousAgent(
            gateway,
            model,
            tool_names=tool_names,
            task_id="langgraph-autonomous-agent",
            recursion_limit=args.recursion_limit,
        )
        run = agent.run(
            args.task,
            context=context,
            source_content=args.task if args.untrusted else "",
            declared_purpose="Autonomously complete the SOC triage task with available tools.",
            report_path=args.report_path,
        )
    except Exception as exc:
        print(
            f"Autonomous agent failed: {_safe_exception_summary(exc)}",
            file=sys.stderr,
        )
        return 1

    print(run.markdown())
    if run.metadata.get("final_message"):
        print()
        print("Final message:")
        print(run.metadata["final_message"])
    print(f"Audit written to {args.audit}")
    return 0


def _cmd_autonomous_benchmark(args: argparse.Namespace) -> int:
    try:
        result = run_autonomous_benchmark(
            tasks_path=args.tasks,
            tools_path=args.tools,
            workspace_root=PROJECT_ROOT,
            output_dir=args.output,
            model_config_path=args.model_config,
            model_name=args.model,
            recursion_limit=args.recursion_limit,
            overwrite=args.overwrite,
        )
    except Exception as exc:
        print(
            f"Autonomous benchmark failed: {_safe_exception_summary(exc)}",
            file=sys.stderr,
        )
        return 1
    print(result.markdown())
    print()
    print(f"Wrote metrics to {Path(args.output) / 'metrics.json'}")
    print(f"Wrote report to {Path(args.output) / 'report.md'}")
    return 0


def _safe_exception_summary(exc: Exception) -> str:
    """Describe a failure without persisting provider response bodies.

    Provider exceptions may echo request prompts, tool arguments, or credentials.
    Their class and numeric HTTP status are sufficient for automated diagnostics;
    callers that need the provider body should inspect it only in an ephemeral,
    access-controlled session.
    """

    name = type(exc).__name__
    status_code = getattr(exc, "status_code", None)
    if isinstance(status_code, int) and 100 <= status_code <= 599:
        return f"{name} (HTTP {status_code})"
    return name


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


def _tool_names_for_explicit_fixtures(
    registry: ToolRegistry,
    enabled_fixture_tools: list[str],
) -> list[str] | None:
    if not enabled_fixture_tools:
        return None
    enabled = set(enabled_fixture_tools)
    unknown = enabled - set(registry.names())
    if unknown:
        raise ValueError(f"Unknown fixture tools: {sorted(unknown)}")
    not_fixtures = sorted(
        name
        for name in enabled
        if not registry.require(name).metadata.get("benchmark_fixture", False)
    )
    if not_fixtures:
        raise ValueError(
            "--enable-fixture-tool only accepts tools marked benchmark_fixture: "
            + ", ".join(not_fixtures)
        )
    return [
        name
        for name in registry.names()
        if not registry.require(name).metadata.get("benchmark_fixture", False)
        or name in enabled
    ]


def _print_demo_result(step_id: str, tool_name: str, decision: dict[str, Any], result: dict[str, Any] | None) -> None:
    decision, _ = SensitiveDataDetector().redact(decision)
    if result is not None:
        result, _ = SensitiveDataDetector().redact(result)
    print(f"[{step_id}] {tool_name}: {decision['decision']} ({decision['risk_level']}) - {decision['reason']}")
    if decision.get("signals"):
        for signal in decision["signals"]:
            print(f"  signal={signal['signal_type']} level={signal['level']} evidence={signal.get('evidence')}")
    if result:
        print("  result=" + json.dumps(result, ensure_ascii=False))


if __name__ == "__main__":
    raise SystemExit(main())
