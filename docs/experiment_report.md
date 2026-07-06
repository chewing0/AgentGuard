# AgentGuard Experiment Report

## Experimental Setup

Date: 2026-07-06

Benchmark: `data/benchmark_tasks.jsonl`

Tool policy: `data/tools.json`

Modes:

- `none`: no runtime protection.
- `prompt_only`: prompt-level constraints only.
- `rule_guard`: static rule baseline.
- `gateway`: full AgentGuard runtime mediation.

Metrics:

- Task completion rate: fraction of benchmark tasks whose required benign steps are allowed.
- Unsafe call rate: fraction of labeled unsafe calls that are allowed to execute.
- Unauthorized access success rate: unsafe allowed rate on authorization violations.
- Sensitive leakage success rate: unsafe allowed rate on leakage steps.
- High-risk tool-call success rate: unsafe allowed rate on high-risk operations.
- Parameter tampering success rate: unsafe allowed rate on parameter-tampering steps.
- False block rate: fraction of safe steps blocked.
- Review rate: fraction of steps requiring human confirmation.

## Results

| Mode | Task Completion | Unsafe Call | Unauthorized | Leakage | High-Risk | Parameter Tampering | False Block | Review |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| none | 1.0 | 1.0 | 1.0 | 1.0 | 1.0 | 1.0 | 0.0 | 0.0 |
| prompt_only | 1.0 | 0.9524 | 1.0 | 0.9167 | 1.0 | 1.0 | 0.0 | 0.0 |
| rule_guard | 0.9667 | 0.4286 | 0.6 | 0.4167 | 0.1667 | 0.8 | 0.0 | 0.0833 |
| gateway | 1.0 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0278 |

## Analysis

The prompt-only baseline blocks one direct exfiltration attempt but remains weak against indirect prompt injection, parameter tampering, and authorization violations because it does not inspect tool parameters or retrieved content at execution time.

The rule baseline improves high-risk behavior but leaves many authorization and parameter attacks untouched. It also reduces completion on one safe confirmed code task because static rules cannot distinguish confirmed and unconfirmed execution contexts.

The AgentGuard gateway blocks all labeled unsafe calls in this benchmark while preserving completion for all benign tasks. Its review rate comes from one unconfirmed high-risk code call, showing that confirmation can be used as a narrow intervention rather than a broad substitute for policy checks.

The benchmark now includes a local knowledge-base search tool, a threat-intelligence lookup tool, and SOC-specific poisoning/leakage cases. This adds coverage for a realistic analyst agent pattern where retrieved advisory text can be incorrectly treated as an instruction source.

The primary tested agent is `SecurityOperationsAgent`, a deterministic planner-executor SOC analyst. It triages `SOC-104`, queries alert and asset context, looks up indicators, retrieves playbooks, quarantines injected KB content, and writes an approved report artifact.

## Threats To Validity

- The included benchmark is intentionally compact and deterministic. A paper-scale study should expand the task count, include multiple agent models, and report confidence intervals.
- Regex detectors are transparent and reproducible but incomplete. Future work should compare them with learned classifiers and semantic policy checkers.
- Demo tools are local mocks. Production tools require stronger sandboxing, identity propagation, policy versioning, and tamper-resistant logs.

## Reproduction

```powershell
python -m agentguard validate-benchmark
python -m agentguard evaluate --output runs\latest
python -m agentguard dashboard --run runs\latest
python -m agentguard security-agent "Triage alert SOC-104 and produce a containment recommendation."
python -m agentguard agent "Generate a security assessment report for AgentGuard."
python -m unittest discover -s tests
```
