# Benchmark 与黑盒场景定义

本目录只保存可复现的任务与测试 case 定义；工具注册和策略仍位于 `data/tools.json`，合成文件沙箱仍位于 `data/demo_workspace/` 与 `data/security_ops_workspace/`。

| 文件 | 用途 |
|---|---|
| `benchmark_tasks.jsonl` | 35 个任务、44 个 tool-call step 的确定性策略回归集 |
| `heldout_benchmark_tasks.jsonl` | 10 个与开发 trace 在 ID、prompt 和 tool-call 指纹上不重叠的冻结留出任务 |
| `benchmark_splits.json` | 固定开发集、留出集与 Provider profile 的 SHA-256、角色和父子关系 |
| `autonomous_benchmark_tasks.jsonl` | 6 个 scripted LangGraph 集成场景 |
| `llm_security_benchmark_tasks.jsonl` | 2 个良性任务和 13 个攻击任务的主研究集 |
| `provider_smoke_benchmark_tasks.jsonl` | 4 个真实模型快速验收任务 |
| `provider_frontier_benchmark_tasks.jsonl` | 5 个真实模型前沿攻击任务 |
| `provider_benchmark_tasks.jsonl` | 旧版三任务 provider pilot 复现集 |
| `blackbox_attack_cases.jsonl` | 11 个公开 CLI 黑盒攻击与良性控制 case |

`provider_smoke_*` 与 `provider_frontier_*` 是主研究集的冻结子集。修改主任务时必须运行全量测试，确认 provider profile 同步检查仍然通过。

运行 `python -m agentguard validate-splits` 会验证文件哈希、路径边界、任务 ID 唯一性、开发/留出指纹无交集，以及 Provider profile 与父集字段同步。`benchmark_splits.json` 还记录 InjecAgent、AgentDojo 和 ASB 的官方来源与当前适配范围；目前只有 InjecAgent 检测语料与通用 paired JSONL 有可执行 adapter，不应把来源登记误写成完整 benchmark 接入。

新增定义时应保留稳定的任务 ID，显式声明安全与 utility oracle，并使用合成数据。运行生成的 audit、manifest、metrics 和报告应写入 `runs/`，不要放入本目录。
