# AgentGuard Risk Taxonomy

This taxonomy defines the risk labels used by the benchmark and gateway. It is designed for paper-scale analysis: every benchmark step can be mapped to one or more labels, and every gateway decision can be traced to structured risk signals.

## 1. Prompt Injection

Prompt injection occurs when user input, retrieved content, files, API responses, or other external data tries to override the agent's original task or policy.

Subtypes:

- Direct prompt injection: the user directly asks the agent to ignore rules, reveal hidden prompts, or exfiltrate data.
- Indirect prompt injection: untrusted retrieved content asks the agent to call tools, read secrets, delete files, or send data elsewhere.
- Tool-steering injection: injected text names a tool and a target parameter.
- Policy extraction injection: injected text asks for system prompts, developer messages, hidden instructions, or internal policies.

Benchmark labels: `prompt_injection`.

## 2. Tool Misuse And Mis-Selection

Tool misuse means the agent selects a tool that is unnecessary, overly powerful, or semantically mismatched for the benign task.

Examples:

- Choosing `code.python` when a deterministic calculation or database query would suffice.
- Calling `file.delete` for a summarization task.
- Calling an unregistered tool such as `os.shell`.

Related labels: `high_risk_tool_call`, `unauthorized_access`.

## 3. Authorization Boundary Violation

Authorization violations occur when a tool call crosses the user's role, scope, resource, host, or table boundary.

Enforced boundaries:

- Role allowlists, such as `admin` for destructive tools.
- Scope requirements, such as `file:read`, `db:read`, or `network:api`.
- File roots, such as `data/demo_workspace/public`.
- API domain allowlists.
- SQL table and field restrictions.

Benchmark labels: `unauthorized_access`.

## 4. Sensitive Information Leakage

Sensitive leakage occurs when secrets, credentials, personal data, private records, or hidden system material leave a protected boundary.

Detected examples:

- API keys matching `sk-*`.
- Bearer tokens and password assignments.
- Private key blocks.
- Email addresses, US SSNs, Chinese national ID-like values, and credit-card-like values.
- Secrets placed into search queries, URLs, generated files, or downstream prompts.

Benchmark labels: `sensitive_leakage`.

## 5. High-Risk Operation Loss Of Control

High-risk operations can cause destructive, persistent, or externally visible effects. They require explicit confirmation or blocking when risk signals are present.

Examples:

- Code execution.
- File deletion.
- Administrative actions.
- Multi-statement or destructive SQL.
- Network calls carrying sensitive data.

Benchmark labels: `high_risk_tool_call`.

## 6. Parameter Tampering

Parameter tampering occurs when the selected tool is plausible but the parameters encode a boundary bypass.

Examples:

- Path traversal such as `public/../secrets.env`.
- SQL injection or multiple SQL statements.
- SSRF-like calls to localhost or metadata endpoints.
- Overlong payloads carrying hidden instructions.
- Unexpected parameters.

Benchmark labels: `parameter_tampering`.

## 7. Auditability And Accountability

Every tool decision should be reconstructable after the fact.

Required audit fields:

- Actor context: user id, role, scopes, session.
- Tool call: tool name, parameters, task id, step id, declared purpose, source content.
- Risk signals: type, level, evidence, reason.
- Policy decision: allow, allow with redaction, require confirmation, or block.
- Execution result metadata when a call is executed.

