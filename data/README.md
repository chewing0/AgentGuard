# 数据目录

`data/` 只保存可复现的基准输入和合成安全沙箱，不应放置真实业务数据、真实账号或真实密钥。任务与黑盒 case 集中在 `benchmarks/`，工具策略和合成 workspace 保持独立。

## 文件分工

| 路径 | 用途 |
|---|---|
| `benchmarks/` | benchmark、provider profile 与黑盒 case 定义；详细索引见目录内 README |
| `benchmarks/benchmark_tasks.jsonl` | 35 个任务、44 个 tool-call step 的确定性策略回归集 |
| `benchmarks/autonomous_benchmark_tasks.jsonl` | 6 个 scripted LangGraph 集成场景 |
| `benchmarks/llm_security_benchmark_tasks.jsonl` | 2 个良性任务和 13 个攻击任务的主研究集 |
| `benchmarks/provider_smoke_benchmark_tasks.jsonl` | 4 个真实模型快速验收任务：2 个良性、2 个直接/间接注入 |
| `benchmarks/provider_frontier_benchmark_tasks.jsonl` | 5 个真实模型前沿攻击任务：编码、多语言、记忆、MCP、多 Agent |
| `benchmarks/provider_benchmark_tasks.jsonl` | 旧版三任务 provider pilot，仅用于复现历史快照 |
| `benchmarks/blackbox_attack_cases.jsonl` | 11 个公开 CLI 黑盒 case：直接/间接/多语言/自适应注入、编码与跨工具外泄、破坏性操作、Agent 感染、休眠记忆、MCP metadata 和良性 hard negative |
| `tools.json` | 工具注册、权限、参数边界和风险策略 |
| `demo_workspace/` | 通用文件、搜索和破坏性调用的合成沙箱 |
| `security_ops_workspace/` | SOC 文档、告警、知识库、私有 token 与报告沙箱 |

## Fixture 与生成物边界

- `secrets.env` 和 `private/cloud_tokens.env` 是故意提交的**假密钥攻击夹具**，只能用于本地测试。
- `demo_workspace/scratch/old.tmp` 是破坏性工具测试目标，不是待清理的临时垃圾。
- benchmark runner 会先把 `data/` 复制到每个任务自己的 `runs/<experiment>/workspaces/`，再在副本中写报告；源 fixture 不应被实验修改。
- 直接运行 demo 或 agent 时，默认报告和审计日志写入被 Git 忽略的 `runs/manual/`。
- `security_ops_workspace/reports/.gitkeep` 只用于保留空报告目录；这里不提交运行生成的 Markdown 报告。

新增场景时，应把不可变输入放在对应 workspace，把实验结果放在 `runs/`，并在 JSONL 中标注预期行为与安全边界。

黑盒测试与 benchmark runner 不同：`tests/blackbox/` 中每个场景有独立代码入口。测试不会导入 Agent、Gateway 或 detector，而是启动新的 CLI 子进程，并根据退出码、标准输出、JSONL 审计、工具调用预算和隔离 workspace 的实际文件变化判定是否失守。`unchanged_paths`、`absent_paths`、`required_artifacts` 与动态 canary 用于同时检查破坏、非法工件、良性 utility 和跨通道泄漏。Audit 只作为测试进程可读的 instrumented oracle，绝不会反馈给被测模型。

`benchmarks/provider_smoke_*` 和 `benchmarks/provider_frontier_*` 是主研究集的冻结子集。`tests/non_blackbox/evaluation/` 中对应的独立 loader 测试会比较除路由 tag 外的全部字段，防止子集与 `benchmarks/llm_security_benchmark_tasks.jsonl` 静默漂移。
