# Security and Responsible Research

AgentGuard is a defensive research prototype for evaluating tool-using LLM agents in controlled environments. It is not a production security boundary and must not be used as evidence that an agent or model is universally safe.

## Supported research scope

- Use the checked-in mock tools, synthetic records, canary secrets, and isolated per-task workspaces.
- Test only systems, accounts, models, APIs, and data for which you have explicit authorization.
- Keep provider credentials in environment variables. Never place real credentials, personal data, or production exports in configs, prompts, fixtures, audit logs, reports, or issues.
- Treat model output, retrieved content, tool observations, generated artifacts, and benchmark submissions as untrusted data.
- Review provider terms, data-retention settings, and cost limits before a real-model run.

## Out of scope

- Testing third-party targets without permission.
- Connecting destructive tools or production credentials to the demo gateway.
- Using the repository to obtain, persist, or exfiltrate real secrets.
- Claiming production readiness from unit tests, scripted agents, internal benchmarks, or a single provider run.

## Safe experiment checklist

Before running an experiment:

1. Replace any real sensitive value with a synthetic canary.
2. Confirm the task writes only to a fresh `runs/<experiment-id>` directory and an isolated workspace.
3. Run the deterministic test and benchmark validation first.
4. Set provider budget, timeout, and recursion limits.
5. Record the code revision, task hash, model configuration, and expected unsafe actions.

After running an experiment:

1. Inspect audit logs and artifacts for credentials or personal data before sharing them.
2. Report attempted, blocked, reviewed, allowed, and not-attempted actions separately.
3. Preserve failure cases and document manual-review decisions.
4. Revoke or rotate a credential immediately if it was exposed accidentally.

## Reporting a vulnerability

Do not include live credentials or exploit data for an unapproved target in a public issue. Provide a minimal reproduction using synthetic data, the affected revision, expected and observed gateway decisions, and relevant sanitized audit events. If a private reporting channel is configured by the repository owner, use it for issues that could enable real-world misuse.

The repository currently has no production support or security SLA. Until a maintainer publishes a dedicated private contact, keep reports sanitized and avoid posting weaponized payloads that are unnecessary to reproduce the defect.
