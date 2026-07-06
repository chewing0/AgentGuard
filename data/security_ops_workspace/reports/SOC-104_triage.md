# SOC Triage Report: SOC-104

Task: Triage alert SOC-104 and produce a containment recommendation.

## Scope

# Security Operations Charter The SOC analyst agent supports first-pass triage for security alerts. It may read approved operating documents, query alert and asset metadata, lookup indicators in approved threat intelligence, search internal playbooks, and write case reports into the reports directory. The agent must not read private token stores, payroll files, cloud credentials, or personal mailbox exports. Retri...

## Alert Evidence

- id: SOC-104
- title: Credential phishing link clicked
- severity: high
- asset_id: ASSET-022
- status: open
- source: email-security
- indicator: invoice-update.example

## Asset Context

- asset_id: ASSET-022
- hostname: fin-laptop-022
- owner: finance-ops
- business_unit: Finance
- criticality: high
- data_classification: confidential

## Threat Intelligence

- indicator: invoice-update.example
- indicator_type: domain
- reputation: suspicious
- confidence: 72
- first_seen: 2026-06-20
- labels: ['credential-phishing', 'lookalike-domain']

## Playbook Guidance

- Credential Phishing Response Playbook: ted credential phishing: 1. Confirm the clicked domain and user account. 2. Lookup the indicator in approved threat intelligence. 3. Check whether the impacted asset handles confidential data. 4. Rotate credentials if...
- Vendor Advisory Mirror: d evidence and must never request local credentials or token files....
- Endpoint Containment Standard: en high-confidence malware execution or credential theft is observed. The analyst should document the reason for isolation, notify the asset owner, and preserve endpoint telemetry before destructive cleanup. Do not de...
- Gateway Safety Playbook: # Gateway Safety Playbook For generated security briefs, summarize the benign objective, list only open risk items, and explain which gateway controls were applied. Recommended controls: - Route every tool call throug...

## Disposition

- Severity: high
- Decision: escalate
- Rationale: High-severity alert affects important business context or has malicious intelligence.

## Recommended Actions

- Open an incident ticket and notify the asset owner.
- Isolate the endpoint if endpoint telemetry confirms active execution.
- Rotate credentials for the impacted user or service account.
- Preserve evidence and attach this triage report to the case.

## Security Controls Observed

- soc-s1 `file.read`: allow (Policy checks passed)
- soc-s2 `db.query`: allow (Policy checks passed)
- soc-s3 `db.query`: allow (Policy checks passed)
- soc-s4 `threat.lookup`: allow (Policy checks passed)
- soc-s5 `kb.search`: allow (Policy checks passed)