# AgentGuard

AgentGuard 是一个可复现实验原型，用于评估和保护 LLM Agent 的工具调用。它关注文件、数据库、代码执行、API、Web 搜索等工具场景中的提示注入、工具滥用、越权访问、敏感数据泄漏、高风险操作和参数篡改。

本仓库默认自包含：benchmark、本地 SOC 工具、运行时网关、基线策略、审计日志、评估指标和测试都可以在没有外部模型或云依赖的情况下运行。需要真实模型时，可以通过 OpenAI 兼容配置把真实 LLM 接入完整 autonomous agent 流程。

## 功能概览

- 运行时安全网关：权限检查、参数约束、风险评分、提示注入检测、敏感数据检测、输出脱敏、高风险确认和审计日志。
- `SecurityOperationsAgent`：面向 SOC 告警研判的 planner-executor agent，可调用文件、数据库、威胁情报、知识库和报告写入工具。
- `DemoAgent`：用于小型项目报告工作流的兼容 demo agent。
- LangGraph 适配器：把 AgentGuard 工具暴露为 LangChain/LangGraph 工具，并支持 `StateGraph` 工具节点。
- `LangGraphAutonomousAgent`：完整的 LangGraph ReAct 风格 LLM agent loop，可作为被攻击 agent 进行评测。
- OpenAI 兼容真实模型配置：支持第三方 base URL，用于真实端到端 autonomous agent 运行。
- Autonomous attack benchmark：评估完整自主 agent 被攻击时的行为，而不只是固定的 labeled tool-call trace。
- 显式防御层 `agentguard/defense/`：复用 `PolicyEngine` 做权限、参数、敏感数据、提示注入和高风险检查。
- 本地知识库工具 `kb.search`：包含良性 playbook 和被投毒的间接提示注入样本。
- 攻击场景目录：覆盖直接提示注入、SOC KB 投毒、多轮间接注入、工具结果投毒、跨工具泄漏、伪造系统指令、长上下文混淆、高风险工具诱导、参数篡改和威胁情报泄漏。
- `data/tools.json`：工具注册表和安全策略配置。
- `data/benchmark_tasks.jsonl`：labeled tool-call benchmark，覆盖正常任务、间接提示注入、直接提示注入、越权访问、泄漏、高风险调用和参数篡改。
- 四种评估模式：`none`、`prompt_only`、`rule_guard`、`gateway`。
- 确定性本地工具后端：文件、SQLite 查询、受限 Python 表达式、mock API、威胁情报查询和 mock 搜索。
- 静态 HTML dashboard：展示指标、审计日志、调用链回放、决策、原因和确认状态。

## 快速开始

```powershell
python -m agentguard validate-benchmark
python -m agentguard evaluate --output runs\latest
python -m agentguard security-agent "Triage alert SOC-104 and produce a containment recommendation."
python -m agentguard agent "Generate a security assessment report for AgentGuard."
python -m pip install -e ".[langgraph]"
python -m agentguard autonomous-agent --simulate-attack --audit runs\autonomous_agent_audit.jsonl
python -m agentguard autonomous-benchmark --output runs\autonomous
python -m agentguard langgraph-demo --audit runs\langgraph_audit.jsonl
python -m agentguard list-attacks
python -m agentguard confirm-demo --approve
python -m agentguard dashboard --run runs\latest
python -m agentguard demo --task ag-inj-001 --audit runs\demo_audit.jsonl
python -m unittest discover -s tests
```

默认评估会写入：

- `runs/latest/metrics.json`
- `runs/latest/report.md`
- `runs/latest/audit/` 下的各模式审计日志

dashboard 命令会生成 `runs/latest/dashboard.html`。

`langgraph` extra 是可选依赖。如果本机已有旧版 `langchain` 包，建议使用虚拟环境，因为 LangGraph 1.x 使用 LangChain Core 1.x。

## 示例结果

在内置 benchmark 上，gateway 能保持正常任务完成，同时阻断所有已标注的不安全调用：

| 模式 | 任务完成率 | 不安全调用率 | 泄漏成功率 | 高风险成功率 |
|---|---:|---:|---:|---:|
| none | 1.0 | 1.0 | 1.0 | 1.0 |
| prompt_only | 1.0 | 0.9524 | 0.9167 | 1.0 |
| rule_guard | 0.9667 | 0.4286 | 0.4167 | 0.1667 |
| gateway | 1.0 | 0.0 | 0.0 | 0.0 |

## 项目结构

```text
agentguard/
  agents/                 SOC agent、DemoAgent 和 agent run trace schema
  adapters/               LangGraph 适配器，用于受保护的外部 agent framework 执行
  audit.py                JSONL 审计写入和摘要工具
  attacks/                内置攻击场景目录
  benchmarks/             benchmark schema 和 loader
  autonomous_evaluation.py autonomous agent benchmark runner
  defense/                显式运行时策略引擎
  detectors.py            提示注入和敏感数据检测器
  evaluation.py           labeled benchmark runner 和指标
  gateway.py              运行时安全网关
  metrics.py              通用评估指标
  policies.py             基线保护策略
  registry.py             工具注册表和策略加载器
  schemas.py              共享 dataclass 和 enum
  tools/                  确定性 demo 工具 handler
  ui/                     静态 HTML dashboard 生成器
data/
  benchmark_tasks.jsonl             labeled tool-call benchmark
  autonomous_benchmark_tasks.jsonl  完整 autonomous-agent 攻击 benchmark
  tools.json                        工具风险和权限策略
  demo_workspace/                   public、shared、KB、private、secret、scratch 文件
  security_ops_workspace/           SOC charter、intake、playbook、private token、report 文件
docs/
  README.md
  taxonomy.md
  system_design.md
  experiment_report.md
  demo.md
  target_system_and_gap_analysis.md
tests/
```

## 扩展原型

新增工具时，在 `data/tools.json` 注册新的 spec，通过 `ToolRegistry.attach_handler` 绑定 handler，并添加 labeled benchmark steps 来覆盖安全和不安全路径。

连接真实 LLM 或开源 agent framework 时，需要在工具后端执行前，把每个候选工具调用路由到 `SecurityGateway.inspect` 或 `SecurityGateway.execute`。内置 `SecurityOperationsAgent` 是确定性的，这样可以保证受保护 agent 行为可复现。

## LangGraph Autonomous Agent

`LangGraphAutonomousAgent` 是需要完整 LLM agent 时的被攻击系统入口。它构建真实 LangGraph state graph：

```text
用户任务 -> LLM 节点 -> 受保护工具节点 -> LLM 节点 -> ... -> 最终回答
```

LLM 通过绑定的 LangChain 工具 schema 选择工具。AgentGuard 仍然通过 `SecurityGateway` 介入执行，记录每个 `AgentStep`，并写入普通 JSONL 审计事件。

本地可复现攻击 demo：

```powershell
python -m pip install -e ".[langgraph]"
python -m agentguard autonomous-agent --simulate-attack --audit runs\autonomous_agent_audit.jsonl
```

默认使用 scripted tool-calling ChatModel，不需要外部 API key。若要使用真实 provider-backed 模型，可以安装对应 provider 包，并传入 LangChain 模型名：

```powershell
python -m agentguard autonomous-agent --model provider:model-name --audit runs\autonomous_agent_audit.jsonl
```

OpenAI 兼容 API 推荐使用 JSON 配置。先复制示例配置，然后通过环境变量提供 key：

```powershell
copy configs\openai-compatible.example.json configs\openai-compatible.local.json
$env:AGENTGUARD_OPENAI_API_KEY = "<your-key>"
python -m pip install -e ".[langgraph,openai]"
python -m agentguard autonomous-agent --model-config configs\openai-compatible.local.json --audit runs\real_autonomous_agent_audit.jsonl
```

配置文件只保存 provider、model、base URL、timeout、temperature、retry 等参数，以及 API key 的环境变量名。`configs/*.local.json` 已加入 `.gitignore`，不会提交真实密钥。

## Autonomous Attack Benchmark

原有 `evaluate` 命令继续用于 labeled trace benchmark。新增 autonomous benchmark 会运行完整 LangGraph agent loop，并评估：

- 必需的良性工具是否完成；
- 预期不安全工具是否被阻断；
- 输出中是否泄漏禁用的 secret pattern。

默认用 scripted model，保证本地和 CI 可复现：

```powershell
python -m pip install -e ".[langgraph]"
python -m agentguard autonomous-benchmark --output runs\autonomous
python -m agentguard dashboard --run runs\autonomous
```

使用真实 OpenAI 兼容模型运行同一任务集：

```powershell
$env:AGENTGUARD_OPENAI_API_KEY = "<your-key>"
python -m pip install -e ".[langgraph,openai]"
python -m agentguard autonomous-benchmark --model-config configs\openai-compatible.local.json --output runs\autonomous_real
```

CI 中的真实模型测试默认不运行。若要启用，需要设置：

- repository variable：`AGENTGUARD_RUN_REAL_MODEL_TESTS=1`
- repository secret：`AGENTGUARD_OPENAI_API_KEY`
- 可选 variables：`AGENTGUARD_OPENAI_BASE_URL`、`AGENTGUARD_OPENAI_MODEL`

示例配置默认兼容 SiliconFlow：

```json
{
  "provider": "openai",
  "model": "Pro/zai-org/GLM-5.1",
  "base_url": "https://api.siliconflow.cn/v1",
  "api_key_env": "AGENTGUARD_OPENAI_API_KEY",
  "timeout_ms": 600000,
  "temperature": 0,
  "max_retries": 2
}
```

## LangGraph Adapter

安装可选集成：

```powershell
python -m pip install -e ".[langgraph]"
```

适配器位于 `agentguard.adapters.LangGraphGatewayAdapter`。它可以：

- 通过 `adapter.as_tools()` 把注册表工具暴露为 LangChain `StructuredTool`；
- 通过 `adapter.tool_node` 作为 LangGraph `StateGraph` 节点运行；
- 把 provider-safe 名称映射回 AgentGuard 工具名，例如 `agentguard__file__read` -> `file.read`；
- 把已执行的 framework 调用记录为普通 `AgentStep` 和审计事件。

最小 graph 接线示例：

```python
from langchain_core.messages import AIMessage
from langgraph.graph import END, START, MessagesState, StateGraph

from agentguard.adapters import LangGraphGatewayAdapter

adapter = LangGraphGatewayAdapter(gateway, context, task_id="langgraph-demo")
builder = StateGraph(MessagesState)
builder.add_node("tools", adapter.tool_node)
builder.add_edge(START, "tools")
builder.add_edge("tools", END)
graph = builder.compile()

graph.invoke({
    "messages": [
        AIMessage(
            content="",
            tool_calls=[{
                "name": adapter.to_framework_tool_name("kb.search"),
                "args": {"query": "gateway report recommendations", "top_k": 2},
                "id": "call-kb",
            }],
        )
    ]
})
```

## 测试

基础测试：

```powershell
python -m unittest discover -s tests
```

Benchmark label 校验：

```powershell
python -m agentguard validate-benchmark
```

Autonomous benchmark smoke test：

```powershell
python -m agentguard autonomous-benchmark --output runs\autonomous
```
