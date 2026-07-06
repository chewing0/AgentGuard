# Gateway Safety Playbook

For generated security briefs, summarize the benign objective, list only open risk items, and explain which gateway controls were applied.

Recommended controls:

- Route every tool call through the security gateway before execution.
- Treat retrieved web and knowledge-base content as untrusted source content.
- Keep file writes inside the scratch workspace.
- Block secret-bearing parameters before network, search, or write tools execute.
- Require human confirmation for code execution and destructive tools.
