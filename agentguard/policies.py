from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any

from .detectors import PromptInjectionDetector, SensitiveDataDetector
from .defense import PolicyEngine
from .gateway import SecurityGateway
from .registry import ToolRegistry
from .schemas import (
    Decision,
    GatewayDecision,
    OperationType,
    RiskLevel,
    RiskSignal,
    RiskSignalType,
    SecurityContext,
    ToolCall,
)


class ProtectionPolicy(ABC):
    name: str

    @abstractmethod
    def inspect(self, call: ToolCall, context: SecurityContext) -> GatewayDecision:
        raise NotImplementedError


class NoProtectionPolicy(ProtectionPolicy):
    name = "none"

    def inspect(self, call: ToolCall, context: SecurityContext) -> GatewayDecision:
        return GatewayDecision(
            decision=Decision.ALLOW,
            risk_level=RiskLevel.LOW,
            reason="No runtime protection",
            sanitized_params=call.params,
        )


class PromptOnlyPolicy(ProtectionPolicy):
    name = "prompt_only"

    def __init__(self) -> None:
        self.detector = PromptInjectionDetector()

    def inspect(self, call: ToolCall, context: SecurityContext) -> GatewayDecision:
        # Prompt-only mitigation represents system-prompt constraints. It sees the
        # user-facing purpose but not untrusted retrieved content or normalized params.
        signals = self.detector.detect(call.declared_purpose)
        risk = max([RiskLevel.LOW, *[signal.level for signal in signals]])
        if any(signal.level >= RiskLevel.CRITICAL for signal in signals):
            return GatewayDecision(Decision.BLOCK, risk, "Prompt constraint rejected obvious malicious request", signals, call.params)
        return GatewayDecision(Decision.ALLOW, risk, "Prompt constraints did not reject the call", signals, call.params)


class RuleGuardPolicy(ProtectionPolicy):
    name = "rule_guard"

    def __init__(self, registry: ToolRegistry) -> None:
        self.registry = registry
        self.sensitive_detector = SensitiveDataDetector()
        self.prompt_detector = PromptInjectionDetector()

    def inspect(self, call: ToolCall, context: SecurityContext) -> GatewayDecision:
        spec = self.registry.get(call.tool_name)
        signals: list[RiskSignal] = []
        if spec is None:
            signals.append(RiskSignal(RiskSignalType.TOOL_POLICY, RiskLevel.HIGH, "Unknown tool", call.tool_name))
            return GatewayDecision(Decision.BLOCK, RiskLevel.HIGH, "Unknown tool", signals, call.params)

        if spec.risk_level >= RiskLevel.CRITICAL:
            signals.append(RiskSignal(RiskSignalType.HIGH_RISK, spec.risk_level, "Critical tool blocked by static rule", spec.name))
            return GatewayDecision(Decision.BLOCK, spec.risk_level, "Static critical-risk rule", signals, call.params)
        if spec.requires_confirmation:
            signals.append(RiskSignal(RiskSignalType.HIGH_RISK, spec.risk_level, "High-risk tool needs review", spec.name))
            return GatewayDecision(Decision.REQUIRE_CONFIRMATION, spec.risk_level, "Static confirmation rule", signals, call.params)

        sensitive = self.sensitive_detector.signals(call.params)
        if sensitive and spec.operation in {OperationType.NETWORK, OperationType.WRITE}:
            signals.extend(sensitive)
            return GatewayDecision(Decision.BLOCK, RiskLevel.CRITICAL, "Static sensitive-flow rule", signals, call.params)

        signals.extend(self.prompt_detector.detect(call.source_content))
        risk = max([spec.risk_level, *[signal.level for signal in signals]])
        if any(signal.level >= RiskLevel.CRITICAL for signal in signals):
            return GatewayDecision(Decision.BLOCK, risk, "Static prompt-injection keyword rule", signals, call.params)
        return GatewayDecision(Decision.ALLOW, risk, "Static rules passed", signals, call.params)


class GatewayPolicy(ProtectionPolicy):
    name = "gateway"

    def __init__(self, gateway: SecurityGateway, name: str = "gateway") -> None:
        self.gateway = gateway
        self.name = name

    def inspect(self, call: ToolCall, context: SecurityContext) -> GatewayDecision:
        return self.gateway.inspect(call, context)


def build_policies(registry: ToolRegistry, gateway: SecurityGateway) -> dict[str, ProtectionPolicy]:
    policies: list[ProtectionPolicy] = [
        NoProtectionPolicy(),
        PromptOnlyPolicy(),
        RuleGuardPolicy(registry),
        GatewayPolicy(gateway),
    ]
    for check in sorted(PolicyEngine.CHECKS):
        engine = PolicyEngine(
            registry,
            workspace_root=gateway.workspace_root,
            disabled_checks={check},
        )
        ablated_gateway = SecurityGateway(
            registry,
            workspace_root=gateway.workspace_root,
            policy_engine=engine,
        )
        policies.append(GatewayPolicy(ablated_gateway, name=f"gateway_without_{check}"))
    return {policy.name: policy for policy in policies}
