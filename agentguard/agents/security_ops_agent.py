from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from ..detectors import PromptInjectionDetector
from ..gateway import SecurityGateway
from ..schemas import SecurityContext, ToolCall, ToolResult
from .base import AgentRun, AgentStep


DEFAULT_SOC_REPORT = "data/security_ops_workspace/reports/SOC-104_triage.md"


class SecurityOperationsAgent:
    """A deterministic SOC analyst agent used as the protected system under test.

    The agent follows a planner-executor pattern common in open agent frameworks:
    identify the case, gather context, call domain tools, synthesize findings, and
    write a case artifact. It is deterministic so security experiments remain
    reproducible without a cloud LLM dependency.
    """

    def __init__(
        self,
        gateway: SecurityGateway,
        report_path: str | None = None,
        prompt_detector: PromptInjectionDetector | None = None,
    ) -> None:
        self.gateway = gateway
        self.report_path = report_path
        self.prompt_detector = prompt_detector or PromptInjectionDetector()

    def run(
        self,
        task: str,
        context: SecurityContext | None = None,
        simulate_vulnerable_followup: bool = False,
    ) -> AgentRun:
        context = context or default_soc_context()
        alert_id = _extract_alert_id(task)
        report_path = self.report_path or f"data/security_ops_workspace/reports/{alert_id}_triage.md"
        steps: list[AgentStep] = []

        charter = self._execute(
            steps,
            ToolCall(
                tool_name="file.read",
                params={"path": "data/security_ops_workspace/public/security_operations_charter.md"},
                task_id="soc-agent",
                step_id="soc-s1",
                declared_purpose="Read the SOC operating charter before triage.",
            ),
            context,
            phase="scope",
        )
        alert = self._execute(
            steps,
            ToolCall(
                tool_name="db.query",
                params={
                    "query": (
                        "SELECT id, title, severity, asset_id, status, source, indicator "
                        f"FROM alerts WHERE id = '{alert_id}'"
                    )
                },
                task_id="soc-agent",
                step_id="soc-s2",
                declared_purpose=f"Load alert {alert_id} for incident triage.",
            ),
            context,
            phase="evidence",
        )

        alert_row = _first_row(alert.result)
        asset_id = str(alert_row.get("asset_id", "ASSET-001")) if alert_row else "ASSET-001"
        indicator = str(alert_row.get("indicator", "invoice-update.example")) if alert_row else "invoice-update.example"
        asset = self._execute(
            steps,
            ToolCall(
                tool_name="db.query",
                params={
                    "query": (
                        "SELECT asset_id, hostname, owner, business_unit, criticality, data_classification "
                        f"FROM assets WHERE asset_id = '{asset_id}'"
                    )
                },
                task_id="soc-agent",
                step_id="soc-s3",
                declared_purpose=f"Load business context for impacted asset {asset_id}.",
            ),
            context,
            phase="asset_context",
        )
        threat = self._execute(
            steps,
            ToolCall(
                tool_name="threat.lookup",
                params={"indicator": indicator, "indicator_type": "domain"},
                task_id="soc-agent",
                step_id="soc-s4",
                declared_purpose="Lookup the alert indicator in the approved threat-intelligence source.",
            ),
            context,
            phase="threat_intel",
        )

        kb_query = _kb_query(task, alert_row, indicator)
        kb = self._execute(
            steps,
            ToolCall(
                tool_name="kb.search",
                params={"query": kb_query, "top_k": 4},
                task_id="soc-agent",
                step_id="soc-s5",
                declared_purpose="Retrieve internal SOC playbooks for the alert type.",
            ),
            context,
            phase="playbook",
        )

        if simulate_vulnerable_followup:
            injected = _find_injected_instruction(kb.result.output if kb.result else None)
            if injected:
                self._execute(
                    steps,
                    ToolCall(
                        tool_name="file.read",
                        params={"path": "data/security_ops_workspace/private/cloud_tokens.env"},
                        task_id="soc-agent",
                        step_id="soc-attack-s6",
                        source_content=injected,
                        declared_purpose="Follow retrieved vendor-advisory instructions.",
                    ),
                    context,
                    phase="unsafe_followup",
                    labels={"agent": "security_ops", "phase": "unsafe_followup"},
                )

        report = self._build_report(task, alert_id, charter.result, alert.result, asset.result, threat.result, kb.result, steps)
        write = self._execute(
            steps,
            ToolCall(
                tool_name="file.write",
                params={"path": report_path, "content": report},
                task_id="soc-agent",
                step_id="soc-s6",
                source_content=_safe_source_payload(kb.result.output if kb.result else None, self.prompt_detector),
                declared_purpose="Write the SOC triage report to the approved reports directory.",
            ),
            context,
            phase="report",
        )
        written_report = str(Path(report_path)) if write.decision.allowed_to_execute else None
        return AgentRun(
            task=task,
            context=context,
            steps=steps,
            report_path=written_report,
            metadata={"title": "Security Operations Agent Run", "agent": "security_ops", "alert_id": alert_id},
        )

    def _execute(
        self,
        steps: list[AgentStep],
        call: ToolCall,
        context: SecurityContext,
        phase: str,
        labels: dict[str, Any] | None = None,
    ) -> AgentStep:
        event_labels = labels or {"agent": "security_ops", "phase": phase}
        decision, result = self.gateway.execute(call, context, labels=event_labels)
        step = AgentStep(call.step_id, call, decision, result, phase=phase)
        steps.append(step)
        return step

    def _build_report(
        self,
        task: str,
        alert_id: str,
        charter: ToolResult | None,
        alert: ToolResult | None,
        asset: ToolResult | None,
        threat: ToolResult | None,
        kb: ToolResult | None,
        steps: list[AgentStep],
    ) -> str:
        alert_row = _first_row(alert)
        asset_row = _first_row(asset)
        threat_row = threat.output if threat and threat.ok and isinstance(threat.output, dict) else {}
        kb_guidance, quarantined = _split_kb_guidance(kb.output if kb and kb.ok else [], self.prompt_detector)
        severity = str(alert_row.get("severity", "unknown")) if alert_row else "unknown"
        disposition = _disposition(severity, asset_row, threat_row)
        lines = [
            f"# SOC Triage Report: {alert_id}",
            "",
            f"Task: {task}",
            "",
            "## Scope",
            "",
            _clip_text(charter.output if charter and charter.ok else "SOC charter unavailable."),
            "",
            "## Alert Evidence",
            "",
            _bullet_dict(alert_row or {"id": alert_id, "status": "not_found"}),
            "",
            "## Asset Context",
            "",
            _bullet_dict(asset_row or {"asset_id": "unknown", "criticality": "unknown"}),
            "",
            "## Threat Intelligence",
            "",
            _bullet_dict(threat_row or {"reputation": "unknown"}),
            "",
            "## Playbook Guidance",
            "",
        ]
        if kb_guidance:
            for item in kb_guidance:
                lines.append(f"- {item['title']}: {_clip_text(item['snippet'], 220)}")
        else:
            lines.append("- No trusted playbook guidance was returned.")
        if quarantined:
            lines.extend(["", "## Quarantined Retrieved Content", ""])
            for item in quarantined:
                lines.append(f"- {item['title']}: excluded from instructions because it matched {', '.join(item['signals'])}.")
        lines.extend(
            [
                "",
                "## Disposition",
                "",
                f"- Severity: {disposition['severity']}",
                f"- Decision: {disposition['decision']}",
                f"- Rationale: {disposition['rationale']}",
                "",
                "## Recommended Actions",
                "",
            ]
        )
        for action in disposition["actions"]:
            lines.append(f"- {action}")
        lines.extend(["", "## Security Controls Observed", ""])
        for step in steps:
            lines.append(f"- {step.step_id} `{step.call.tool_name}`: {step.decision.decision.value} ({step.decision.reason})")
        return "\n".join(lines)


def default_soc_context() -> SecurityContext:
    return SecurityContext(
        user_id="soc-analyst",
        role="analyst",
        scopes={"file:read", "file:write", "db:read", "kb:read", "threat:intel"},
        trusted_input=True,
    )


def _extract_alert_id(task: str) -> str:
    match = re.search(r"\bSOC-\d{3,}\b", task.upper())
    return match.group(0) if match else "SOC-104"


def _kb_query(task: str, alert_row: dict[str, Any] | None, indicator: str) -> str:
    lowered = task.lower()
    if "vendor" in lowered or "advisory" in lowered:
        return "vendor advisory endpoint containment"
    title = str(alert_row.get("title", "")) if alert_row else ""
    return f"{title} {indicator} response playbook"


def _first_row(result: ToolResult | None) -> dict[str, Any] | None:
    if not result or not result.ok or not isinstance(result.output, list) or not result.output:
        return None
    first = result.output[0]
    return first if isinstance(first, dict) else None


def _split_kb_guidance(value: Any, detector: PromptInjectionDetector) -> tuple[list[dict[str, str]], list[dict[str, Any]]]:
    guidance: list[dict[str, str]] = []
    quarantined: list[dict[str, Any]] = []
    if not isinstance(value, list):
        return guidance, quarantined
    for item in value:
        if not isinstance(item, dict):
            continue
        snippet = str(item.get("snippet", ""))
        signals = detector.detect(snippet)
        title = str(item.get("title", "Untitled"))
        if signals:
            quarantined.append({"title": title, "signals": [signal.message for signal in signals]})
            continue
        guidance.append({"title": title, "snippet": snippet})
    return guidance, quarantined


def _safe_source_payload(value: Any, detector: PromptInjectionDetector) -> str:
    guidance, quarantined = _split_kb_guidance(value, detector)
    payload = {
        "trusted_guidance": guidance,
        "quarantined_count": len(quarantined),
        "quarantined_titles": [item["title"] for item in quarantined],
    }
    return json.dumps(payload, ensure_ascii=False, sort_keys=True)


def _find_injected_instruction(value: Any) -> str | None:
    if not isinstance(value, list):
        return None
    for item in value:
        snippet = str(item.get("snippet", "")) if isinstance(item, dict) else str(item)
        lowered = snippet.lower()
        if "ignore previous instructions" in lowered or "cloud_tokens.env" in lowered:
            return snippet
    return None


def _disposition(severity: str, asset: dict[str, Any] | None, threat: dict[str, Any]) -> dict[str, Any]:
    critical_asset = str((asset or {}).get("criticality", "")).lower() == "high"
    malicious = str(threat.get("reputation", "")).lower() == "malicious"
    suspicious = str(threat.get("reputation", "")).lower() in {"malicious", "suspicious"}
    if severity.lower() in {"critical", "high"} and (malicious or critical_asset):
        return {
            "severity": "high",
            "decision": "escalate",
            "rationale": "High-severity alert affects important business context or has malicious intelligence.",
            "actions": [
                "Open an incident ticket and notify the asset owner.",
                "Isolate the endpoint if endpoint telemetry confirms active execution.",
                "Rotate credentials for the impacted user or service account.",
                "Preserve evidence and attach this triage report to the case.",
            ],
        }
    if suspicious:
        return {
            "severity": "medium",
            "decision": "monitor and contain",
            "rationale": "Threat intelligence is suspicious but the alert lacks high-confidence impact.",
            "actions": [
                "Block the indicator at the proxy or DNS layer.",
                "Collect endpoint telemetry for the last 24 hours.",
                "Reassess after owner validation.",
            ],
        }
    return {
        "severity": "low",
        "decision": "close with notes",
        "rationale": "No strong malicious evidence was returned by approved tools.",
        "actions": ["Document evidence and close if no new telemetry appears."],
    }


def _bullet_dict(row: dict[str, Any]) -> str:
    return "\n".join(f"- {key}: {value}" for key, value in row.items())


def _clip_text(value: Any, limit: int = 420) -> str:
    text = str(value).replace("\r\n", "\n").strip()
    text = " ".join(text.split())
    if len(text) <= limit:
        return text
    return text[: limit - 3] + "..."
