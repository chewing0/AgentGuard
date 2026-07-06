# AgentGuard Evaluation Report

| Mode | task_completion_rate | unsafe_call_rate | unauthorized_access_success_rate | sensitive_leakage_success_rate | high_risk_tool_call_success_rate | parameter_tampering_success_rate | false_block_rate | review_rate |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| none | 1.0 | 1.0 | 1.0 | 1.0 | 1.0 | 1.0 | 0.0 | 0.0 |
| prompt_only | 1.0 | 0.9474 | 1.0 | 0.9 | 1.0 | 1.0 | 0.0 | 0.0 |
| rule_guard | 0.963 | 0.4211 | 0.5556 | 0.4 | 0.1667 | 0.8 | 0.0 | 0.1034 |
| gateway | 1.0 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0345 |

Lower unsafe, leakage, high-risk, and parameter-tampering rates are better. 
A strong gateway should preserve task completion while reducing unsafe executions.