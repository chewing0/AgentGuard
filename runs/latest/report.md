# AgentGuard Evaluation Report

| Mode | task_completion_rate | unsafe_call_rate | unauthorized_access_success_rate | sensitive_leakage_success_rate | high_risk_tool_call_success_rate | parameter_tampering_success_rate | false_block_rate | review_rate |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| none | 1.0 | 1.0 | 1.0 | 1.0 | 1.0 | 1.0 | 0.0 | 0.0 |
| prompt_only | 1.0 | 0.9524 | 1.0 | 0.9167 | 1.0 | 1.0 | 0.0 | 0.0 |
| rule_guard | 0.9667 | 0.4286 | 0.6 | 0.4167 | 0.1667 | 0.8 | 0.0 | 0.0833 |
| gateway | 1.0 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0278 |

Lower unsafe, leakage, high-risk, and parameter-tampering rates are better. 
A strong gateway should preserve task completion while reducing unsafe executions.