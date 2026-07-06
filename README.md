# AgentGuard

AgentGuard is a reproducible prototype for evaluating and protecting LLM agent tool calls. It targets prompt injection, tool misuse, authorization bypass, sensitive data leakage, high-risk actions, and parameter tampering across file, database, code execution, API, and web-search tools.

This repository is intentionally self-contained: the benchmark, demo tools, gateway, baselines, audit logs, evaluation metrics, and tests run without external model or cloud dependencies. A real agent can be connected later by emitting the same `ToolCall` objects before tool execution.

## What Is Included

- Runtime security gateway with permission checks, parameter constraints, risk scoring, prompt-injection detection, sensitive data detection, redaction, high-risk confirmation, and audit logging.
- Rule-based `DemoAgent` that accepts a natural-language task and runs a complete file-read, database-query, knowledge-base-search, report-generation workflow.
- Explicit defense layer in `agentguard/defense/` with a reusable `PolicyEngine` for permission, parameter, sensitive-data, prompt-injection, and high-risk checks.
- Local knowledge-base tool `kb.search`, including benign guidance documents and a poisoned indirect-prompt-injection sample.
- Built-in attack scenario catalog covering direct prompt injection, KB poisoning, high-risk tool steering, and parameter tampering.
- Tool registry and policy configuration in `data/tools.json`.
- Benchmark task set in `data/benchmark_tasks.jsonl`, covering normal tasks, indirect prompt injection, direct prompt injection, unauthorized access, leakage, high-risk calls, and parameter tampering.
- Four evaluation modes: `none`, `prompt_only`, `rule_guard`, and `gateway`.
- Deterministic demo tool backend for files, SQLite queries, constrained Python expression evaluation, mock APIs, and mock search.
- Static HTML dashboard generation for metrics, audit logs, call-chain replay, decisions, reasons, and confirmation display.
- Documentation for risk taxonomy, system design, experiments, and demos.

## Quick Start

```powershell
python -m agentguard validate-benchmark
python -m agentguard evaluate --output runs\latest
python -m agentguard agent "Generate a security assessment report for AgentGuard."
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

## Example Result

On the included benchmark, the gateway preserves normal task completion while blocking all labeled unsafe calls:

| Mode | Task Completion | Unsafe Call Rate | Leakage Success | High-Risk Success |
|---|---:|---:|---:|---:|
| none | 1.0 | 1.0 | 1.0 | 1.0 |
| prompt_only | 1.0 | 0.9474 | 0.9 | 1.0 |
| rule_guard | 0.963 | 0.4211 | 0.4 | 0.1667 |
| gateway | 1.0 | 0.0 | 0.0 | 0.0 |

## Project Layout

```text
agentguard/
  agents/               deterministic DemoAgent and run trace schema
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

To add a tool, register a new spec in `data/tools.json`, attach a handler through `ToolRegistry.attach_handler`, and add labeled benchmark steps that exercise safe and unsafe paths. To connect a real LLM agent, route every proposed tool call through `SecurityGateway.inspect` or `SecurityGateway.execute` before the tool backend is invoked. The included `DemoAgent` is intentionally rule-based so the whole prototype remains deterministic.
