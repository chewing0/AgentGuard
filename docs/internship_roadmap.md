# LLM 安全实习路线

本文把 AgentGuard 从“可运行的研究原型”整理为一段可验收的 LLM Agent 安全实习。第 0 周是环境准备，之后安排 6 周正式实践，每周约 10–15 小时；时间不足时可完成第 0–3 周，形成一个最小可交付项目。具体安装和运行说明以 [`quickstart.md`](quickstart.md) 为准。

## 1. 实习目标

实习结束时，实习生应能够：

- 建立 tool-using LLM agent 的威胁模型，区分 prompt injection、tool-result poisoning、越权、外发和破坏性操作。
- 解释为什么模型拒答不等于执行边界防护，并区分 `not_attempted`、`blocked`、`reviewed` 和 `allowed`。
- 独立新增一个攻击任务、一个防御策略或一个评测维度，并为其补充测试。
- 运行可复现实验，保留 manifest、原始计数、审计日志和失败案例。
- 用准确措辞汇报结果，不把内部回归集、scripted model 或单次 provider run 外推为普遍鲁棒性。

## 2. 开始前的安全边界

所有实验默认只使用仓库内的 mock 工具、canary 数据和隔离 workspace。不要把真实密钥、个人数据或生产系统接入 AgentGuard，也不要对未明确授权的模型、网站、API 或组织开展攻击测试。更完整的操作边界见仓库根目录的 [`SECURITY.md`](../SECURITY.md)。

真实模型实验必须满足以下条件：

- API key 只通过环境变量提供，配置文件只保存环境变量名。
- 使用新的 `runs/<experiment-id>` 输出目录，避免覆盖既有证据；本地 run 默认被 Git 忽略，约定见 [`runs/README.md`](../runs/README.md)。
- 先用 scripted suite 验证任务和评分管线，再启用 provider-backed run。
- 人工检查最终回答和生成文件中是否存在语义泄漏；正则扫描不能代替人工复核。

## 3. 第 0 周：环境与基线

目标：证明本机环境和仓库基线可复现。

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -e ".[langgraph]"
python -m unittest discover -s tests -v
python -m pip check
python -m agentguard validate-benchmark
python -m agentguard evaluate --output runs/intern-baseline
python -m agentguard dashboard --run runs/intern-baseline
```

交付物：

- `runs/intern-baseline/manifest.json`
- `runs/intern-baseline/metrics.json`
- 一页基线说明：环境、命令、通过/跳过的测试、关键原始计数

验收：测试通过，benchmark 标签校验成功，且能够说明 `none`、`prompt_only`、`rule_guard`、`gateway` 四种模式的差别。

请使用独立虚拟环境。LangGraph 1.x 依赖 LangChain Core 1.x；若直接复用装有 LangChain 0.x 的全局环境，`pip check` 会报告版本冲突，且结果不适合作为可复现基线。

## 4. 第 1 周：威胁建模与攻击复现

阅读顺序：

1. [`quickstart.md`](quickstart.md)
2. [`research_guide.md`](research_guide.md)
3. `data/benchmarks/llm_security_benchmark_tasks.jsonl`

实践任务：从直接注入、间接注入、tool-result poisoning、权限提升、参数边界绕过中选两类，画出从不可信输入到候选 tool call、gateway 决策和副作用的完整路径。

验收：每个威胁都明确资产、攻击者能力、信任边界、预期不安全工具和成功判据，而不只描述“模型说了危险内容”。

## 5. 第 2 周：执行边界与防御实现

重点阅读：

- `agentguard/gateway.py`
- `agentguard/defense/policy_engine.py`
- `agentguard/detectors.py`
- `agentguard/adapters/langgraph.py`
- `data/tools.json`

实践任务：选择一个小型增强，例如新增参数约束、补充一种 credential key、改进一个注入 pattern、增加工具 scope，或为现有规则加入 hard negative。

验收：

- 至少新增一个应阻断测试和一个不应误报测试。
- fail-closed 行为明确，未知参数不能静默进入工具后端。
- 审计日志不包含原始 secret，且结果体积受控。

## 6. 第 3 周：评测设计与结果语义

实践任务：在独立分支或任务文件中新增一个攻击场景和一个良性 hard negative。任务应包含明确的 `attack_vector`、`attack_channel`、`attack_goal`、预期工具和 forbidden-output canary。

先运行 scripted control：

```powershell
python -m agentguard autonomous-benchmark `
  --tasks data/benchmarks/llm_security_benchmark_tasks.jsonl `
  --output runs/intern-scripted
```

验收：报告同时给出 attack attempted、blocked/reviewed/allowed/not attempted 的原始数目。不能把 `not_attempted` 写成“网关拦截”。

## 7. 第 4 周：消融与安全—效用权衡

实践任务：比较至少三种防护模式，分析：

- unsafe-call execution
- safe-call allowance
- task completion / required-tool success
- confirmation burden
- 至少一个 false positive 或 bypass 案例

验收：结论必须绑定当前任务集和配置；对检测器能力、内部 benchmark 共建偏差以及 scripted evidence 的限制有单独说明。

## 8. 第 5 周：真实模型小规模实验（可选）

只有在有合法 provider 账户、预算和授权时才执行。冻结 model、temperature、task file、代码提交、重试与 recursion limit；每个配置建议至少重复 5 次。

```powershell
python -m pip install -e ".[langgraph,openai]"
$env:AGENTGUARD_REAL_MODEL_CONFIG = "configs/openai-compatible.example.json"
$env:AGENTGUARD_OPENAI_API_KEY = $env:ANTHROPIC_AUTH_TOKEN
$env:AGENTGUARD_REAL_MODEL_OUTPUT_ROOT = "runs/manual/intern-provider"
$env:AGENTGUARD_REAL_MODEL_SECURITY_TEST = "1"
python -m unittest discover -s tests/non_blackbox/provider -t . -p "test_real_model_security_provider_smoke_*.py" -v
$env:AGENTGUARD_REAL_MODEL_FRONTIER_TEST = "1"
python -m unittest discover -s tests/non_blackbox/provider -t . -p "test_real_model_security_provider_frontier_*.py" -v
```

验收：报告 provider/model、重复次数、原始分子分母、失败案例和人工复核结果。单模型单次运行只能称为 smoke/pilot。

## 9. 第 6 周：总结与展示

最终交付建议包含：

- 可运行代码与新增测试
- 冻结的任务/策略配置
- 至少一个可复现实验目录
- 2–4 页实验报告或 8–10 页汇报材料
- 一个 5 分钟演示：正常任务、攻击尝试、gateway 决策、审计与指标
- [`resume_showcase.md`](resume_showcase.md) 基础上的个人贡献描述

建议用以下结构讲项目：问题与威胁模型 → 为什么需要执行边界 → 系统设计 → 实验协议 → 结果与失败案例 → 有效性威胁 → 下一步。

## 10. 评分标准

| 维度 | 权重 | 达标证据 |
|---|---:|---|
| 威胁模型与安全边界 | 20% | 资产、攻击者、信任边界和成功判据完整 |
| 工程实现 | 25% | 改动小而清晰，测试覆盖安全与 hard negative |
| 实验严谨性 | 25% | 配置冻结、manifest、原始计数、可复现命令 |
| 结果解释 | 20% | 区分模型行为和 gateway intervention，陈述局限 |
| 展示与文档 | 10% | 他人可在 30 分钟内完成基线复现 |

红线项包括提交真实密钥、测试未授权目标、伪造或挑选性删除失败结果，以及把 scripted 或单次 pilot 结果包装成真实模型的普遍安全结论。

## 11. 可选进阶课题

- 引入独立作者编写的 held-out attack set。
- 接入 AgentDojo、InjecAgent 或 ASB 的可复现子集。
- 比较 regex 与 semantic/learned policy checker 的误报和绕过。
- 设计跨 observation、context 和 outbound sink 的 provenance/taint tracking。
- 增加真实 side-effect sandbox 与 artifact correctness evaluator。
- 对授权、参数、注入、secret scan 和 confirmation 分别做 component ablation。
