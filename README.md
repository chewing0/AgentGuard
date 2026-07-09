# AgentGuard

AgentGuard is a reproducible prototype for evaluating and protecting LLM agent tool calls. It targets prompt injection, tool misuse, authorization bypass, sensitive data leakage, high-risk actions, and parameter tampering across file, database, code execution, API, and web-search tools.

This repository is intentionally self-contained: the benchmark, local SOC tools, gateway, baselines, audit logs, evaluation metrics, and tests run without external model or cloud dependencies. A real or open-source agent framework can be connected later by emitting the same `ToolCall` objects before tool execution.

## What Is Included

- Runtime security gateway with permission checks, parameter constraints, risk scoring, prompt-injection detection, sensitive data detection, redaction, high-risk confirmation, and audit logging.
- `SecurityOperationsAgent`, a planner-executor SOC analyst agent that triages alerts with file, database, threat-intelligence, knowledge-base, and report-writing tools.
- Compatibility `DemoAgent` for the smaller project-report workflow.
- LangGraph adapter that exposes registered AgentGuard tools as guarded LangGraph/LangChain tools and as a `StateGraph` tool node.
- `LangGraphAutonomousAgent`, a full LangGraph ReAct-style LLM agent loop that can be used as the attacked agent under test.
- Explicit defense layer in `agentguard/defense/` with a reusable `PolicyEngine` for permission, parameter, sensitive-data, prompt-injection, and high-risk checks.
- Local knowledge-base tool `kb.search`, including benign playbooks and poisoned indirect-prompt-injection samples.
- Built-in attack scenario catalog covering direct prompt injection, SOC KB poisoning, high-risk tool steering, parameter tampering, and secret leakage through threat intelligence.
- Tool registry and policy configuration in `data/tools.json`.
- Benchmark task set in `data/benchmark_tasks.jsonl`, covering normal tasks, indirect prompt injection, direct prompt injection, unauthorized access, leakage, high-risk calls, and parameter tampering.
- Four evaluation modes: `none`, `prompt_only`, `rule_guard`, and `gateway`.
- Deterministic local tool backend for files, SQLite alert/asset/ticket queries, constrained Python expression evaluation, mock APIs, threat-intelligence lookup, and mock search.
- Static HTML dashboard generation for metrics, audit logs, call-chain replay, decisions, reasons, and confirmation display.
- Documentation for risk taxonomy, system design, experiments, and demos.

## Quick Start

```powershell
python -m agentguard validate-benchmark
python -m agentguard evaluate --output runs\latest
python -m agentguard security-agent "Triage alert SOC-104 and produce a containment recommendation."
python -m agentguard agent "Generate a security assessment report for AgentGuard."
python -m pip install -e ".[langgraph]"
python -m agentguard autonomous-agent --simulate-attack --audit runs\autonomous_agent_audit.jsonl
python -m agentguard langgraph-demo --audit runs\langgraph_audit.jsonl
python -m agentguard list-attacks
python -m agentguard confirm-demo --approve
python -m agentguard dashboard --run runs\latest
python -m agentguard demo --task ag-inj-001 --audit runs\demo_audit.jsonl
python -m unittest discover -s tests
```

The default evaluation writes:

- `runs/latest/metrics.json`
- `runs/latest/report.md`
- per-mode audit logs under `runs/latest/audit/`

The dashboard command writes `runs/latest/dashboard.html`.

The LangGraph extra is optional. Use a virtual environment if you already have older `langchain` packages installed, because LangGraph 1.x uses LangChain Core 1.x.

## Example Result

On the included benchmark, the gateway preserves normal task completion while blocking all labeled unsafe calls:

| Mode | Task Completion | Unsafe Call Rate | Leakage Success | High-Risk Success |
|---|---:|---:|---:|---:|
| none | 1.0 | 1.0 | 1.0 | 1.0 |
| prompt_only | 1.0 | 0.9524 | 0.9167 | 1.0 |
| rule_guard | 0.9667 | 0.4286 | 0.4167 | 0.1667 |
| gateway | 1.0 | 0.0 | 0.0 | 0.0 |

## Project Layout

```text
agentguard/
  agents/               SOC SecurityOperationsAgent, DemoAgent, and run trace schema
  adapters/             LangGraph adapter for guarded external agent framework execution
  audit.py              JSONL audit writer and summary utilities
  attacks/              built-in attack scenario catalog
  benchmarks/           benchmark schema and loader
  defense/              explicit policy engine for runtime checks
  detectors.py          prompt-injection and sensitive-data detectors
  evaluation.py         benchmark runner and metrics
  gateway.py            runtime security gateway
  metrics.py            shared evaluation metric definitions
  policies.py           baseline policies
  registry.py           tool registry and policy loader
  schemas.py            shared dataclasses and enums
  tools/                deterministic demo tool handlers
  ui/                   static HTML dashboard generator
data/
  benchmark_tasks.jsonl labeled tool-call benchmark
  tools.json            tool risk and permission policies
  demo_workspace/       public, shared, KB, private, secret, and scratch files
  security_ops_workspace/ SOC charter, intake, playbooks, private tokens, and reports
docs/
  README.md
  taxonomy.md
  system_design.md
  experiment_report.md
  demo.md
  target_system_and_gap_analysis.md
tests/
```

## Extending The Prototype

To add a tool, register a new spec in `data/tools.json`, attach a handler through `ToolRegistry.attach_handler`, and add labeled benchmark steps that exercise safe and unsafe paths. To connect a real LLM or open-source agent, route every proposed tool call through `SecurityGateway.inspect` or `SecurityGateway.execute` before the tool backend is invoked. The included `SecurityOperationsAgent` is intentionally deterministic so the protected-agent behavior remains reproducible.

## LangGraph Autonomous Agent

`LangGraphAutonomousAgent` is the attacked-agent entry point when the experiment needs a complete LLM agent rather than a fixed deterministic workflow. It builds a real LangGraph state graph:

```text
user task -> LLM node -> guarded tool node -> LLM node -> ... -> final answer
```

The LLM chooses tools through bound LangChain tool schemas. AgentGuard still mediates execution through `SecurityGateway`, records each `AgentStep`, and writes normal JSONL audit events.

Local reproducible attack demo:

```powershell
python -m pip install -e ".[langgraph]"
python -m agentguard autonomous-agent --simulate-attack --audit runs\autonomous_agent_audit.jsonl
```

By default this uses a scripted tool-calling ChatModel so the run is reproducible without an external API key. To use a real provider-backed model, install the provider package and pass a LangChain model name:

```powershell
python -m agentguard autonomous-agent --model provider:model-name --audit runs\autonomous_agent_audit.jsonl
```

## LangGraph Adapter

Install the optional integration:

```powershell
python -m pip install -e ".[langgraph]"
```

The adapter lives in `agentguard.adapters.LangGraphGatewayAdapter`. It can:

- expose registry entries as LangChain `StructuredTool` objects through `adapter.as_tools()`;
- run as a LangGraph `StateGraph` node through `adapter.tool_node`;
- map provider-safe names such as `agentguard__file__read` back to registered AgentGuard tools such as `file.read`;
- record the executed framework calls as normal `AgentStep` entries and audit events.

Minimal graph wiring:

```python
from langchain_core.messages import AIMessage
from langgraph.graph import END, START, MessagesState, StateGraph

from agentguard.adapters import LangGraphGatewayAdapter

adapter = LangGraphGatewayAdapter(gateway, context, task_id="langgraph-demo")
builder = StateGraph(MessagesState)
builder.add_node("tools", adapter.tool_node)
builder.add_edge(START, "tools")
builder.add_edge("tools", END)
graph = builder.compile()

graph.invoke({
    "messages": [
        AIMessage(
            content="",
            tool_calls=[{
                "name": adapter.to_framework_tool_name("kb.search"),
                "args": {"query": "gateway report recommendations", "top_k": 2},
                "id": "call-kb",
            }],
        )
    ]
})
```
