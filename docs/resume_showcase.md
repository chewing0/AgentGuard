# AgentGuard 简历展示版

## 一句话价值定位

围绕 prompt injection、tool-result poisoning、权限提升与数据外发研究 tool-using LLM Agent 安全，并实现工具执行边界防御；内部确定性回归集允许 18/18 个 safe calls，并阻止 26/26 个 unsafe calls 立即执行。

## 可直接放简历的描述

- 研究 execution-boundary mediation 对 LLM Agent 工具误用的防护效果；构建组合式运行时网关，在 `file`、`db`、`api`、`kb.search`、`threat.lookup`、`code.python` 等工具执行前统一实施 role/scope 授权、参数约束、提示注入检测和高风险确认。
- 实现基于正则的 outbound secret-pattern 扫描与输出脱敏，并通过 JSONL 记录策略信号和决策；该实现不声称具备端到端数据流或 taint tracking。
- 构建 35-task、44-step 的内部确定性 labeled regression set；允许 18/18 个 safe calls，并阻止 26/26 个 unsafe calls 立即执行，其中 25 个 `block`、1 个 `require_confirmation`。
- 构建 15-task LLM security suite，按 attack vector、attack channel 和 attack goal 标注 13 类攻击，覆盖直接/间接注入、tool-result poisoning、编码外发、权限提升、多语言、多轮、持久记忆休眠投毒、MCP 工具元数据投毒和 Agent 间提示感染，并分别统计模型未尝试、网关阻断、人工复核与危险执行。
- 实现可插拔 LangGraph adapter 和 6-scenario scripted integration suite，回归 tool observation、拦截结果回传和后续安全步骤；不将 scripted ChatModel 结果表述为 provider-backed attack evidence。
- 建立 99 项自动化测试、GitHub Actions CI、benchmark label 校验、按威胁维度输出的安全报告、JSONL 审计，以及分别门控的 provider-backed 良性 E2E、frontier 与 11 项进程级黑盒测试。

简历标题建议使用 **Research Intern — LLM Agent Security**，项目副标题使用 **AgentGuard: Runtime Policy Enforcement for Tool-Using LLM Agents**。在组织、日期和导师信息旁明确个人负责的模块；只有确实由本人完成的设计、实现和实验才使用“设计/实现/构建”等动词。

## 贡献边界与措辞

当前最准确的定位是 **LLM agent security evaluation and runtime enforcement research prototype**。贡献在于构建 LLM 攻击任务与结果语义，并把授权、参数约束、正则检测、人工确认和审计组合到统一工具执行边界。避免使用“首次提出 tool firewall”“消除 Agent 攻击”“SOTA”“生产级”或“已证明真实模型鲁棒”等表述。

## 展示资产

- Benchmark 前后对比图：`docs/assets/benchmark-comparison.svg`
- Dashboard summary graphic（不是产品截图）：`docs/assets/dashboard-summary.svg`
- Scripted LangGraph integration suite：`docs/assets/scripted-langgraph-suite.svg`
- 架构图：`docs/assets/architecture.svg`
- 可浏览的静态 dashboard（确认按钮仅作界面演示）：`runs/latest/dashboard.html`、`runs/autonomous/dashboard.html`

## 面试讲解重点

**为什么不是只靠 system prompt？**
模型可能被检索内容、工具结果或长上下文中的恶意文本诱导，prompt 约束不会天然阻止真实 API、文件或数据库副作用。AgentGuard 把控制点放在工具执行边界，基于真实参数和上下文做可审计决策。

**为什么需要三层安全评测？**
Labeled trace benchmark 回归策略判断；scripted LangGraph suite 回归 agent loop 与拦截反馈；LLM security suite 冻结攻击向量、通道、目标和模型预期行为，供真实 provider 重复运行。前两层证明实现正确，第三层才用于研究模型是否服从攻击以及网关是否在真实尝试上生效。

**为什么分 gateway、policy engine、adapter？**
Adapter 隔离框架差异，policy engine 聚合安全判断，gateway 管执行、脱敏、确认和审计。这个分层让新增 LangGraph、其他 agent framework 或新工具时，不需要重写核心策略。

## 真实模型实验状态

当前仓库支持 OpenAI-compatible provider 配置，并把付费测试拆成精确工具 E2E、4-task smoke 和 5-task frontier 三个 gate。2026-07-14 的 SiliconFlow GLM-5.1 单次运行中，E2E 与 smoke 通过，frontier 为 4/5：危险工具执行为 0，但模型在编码外发任务中直接输出了解码后的合成 canary，输出泄漏 gate 正确失败。最准确的表述是“构建真实 Agent 分层测试并发现工具执行安全与最终回答安全之间的边界”，不能写成“frontier 全部通过”或“消除了提示注入”。

2026-07-12 的早期三任务 pilot 仍保留用于历史复现，其中两个攻击场景是 `not_attempted`，不能表述为网关拦截。两个快照都是 GLM-5.1、单次运行，尚不足以支持跨模型结论。

补真实模型结果时运行：

```powershell
python -m pip install -e ".[langgraph,openai]"
$env:AGENTGUARD_REAL_MODEL_CONFIG = "configs/openai-compatible.example.json"
$env:AGENTGUARD_OPENAI_API_KEY = $env:ANTHROPIC_AUTH_TOKEN
$env:AGENTGUARD_REAL_MODEL_OUTPUT_ROOT = "runs/manual/provider-siliconflow"
$env:AGENTGUARD_REAL_MODEL_SECURITY_TEST = "1"
python -m unittest discover -s tests/non_blackbox/provider -t . -p "test_real_model_security_provider_smoke_*.py" -v
$env:AGENTGUARD_REAL_MODEL_FRONTIER_TEST = "1"
python -m unittest discover -s tests/non_blackbox/provider -t . -p "test_real_model_security_provider_frontier_*.py" -v
```

只有在冻结任务和模型版本、运行重复试验并人工核验真实环境结果后，才建议在简历中写 provider-backed 模型的 attack success、utility、latency 或 cost 数字。单次 pilot 不足以支持泛化结论。
