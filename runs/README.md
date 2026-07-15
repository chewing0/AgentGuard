# 运行结果目录

`runs/` 保存评测、agent demo 和审计输出。输入定义放在 `data/`，源码不应依赖某次运行产生的文件。

## 已提交的参考快照

| 目录 | 内容 | 解释边界 |
|---|---|---|
| `latest/` | 35-task、44-step 的四种防护模式对比 | 确定性策略回归，不代表未知攻击泛化 |
| `autonomous/` | 6 个 scripted LangGraph 场景 | 验证 agent loop 与网关接线，不代表真实模型鲁棒性 |
| `llm_security_scripted/` | 15-task LLM 安全研究集的 scripted control | 验证攻击路径与评分管线 |
| `provider_glm/` | GLM-5.1 的一次小规模 pilot | `n=1` smoke test，不可外推 |
| `provider_siliconflow/` | 2026-07-14 GLM-5.1 真实 Agent smoke/frontier | E2E、smoke 通过；frontier 4/5，编码载荷触发 1 个输出泄漏 |

每个标准 run 使用相同结构：

```text
<run-id>/
  manifest.json    输入 hash、配置、环境和 Git 状态
  metrics.json     机器可读指标
  report.md        中文/英文实验摘要
  dashboard.html   可选静态结果页面，由 dashboard 命令生成
  audit/           每个模式或任务的 JSONL 审计日志
  workspaces/      每任务隔离副本，本地生成且不提交
```

参考快照不会随每次代码改动自动更新。复现时以各目录 `manifest.json` 中的输入 SHA-256、模型配置和 Git 状态为准；若 hash 与当前文件不同，应创建新 run，而不是把历史指标当作当前代码的结果。`provider_glm/` 是历史 pilot；`provider_siliconflow/` 来自 dirty worktree，必须连同 manifest 的 commit、dirty 标志和输入 hash 一起解释。

部分历史 manifest 生成于 benchmark 目录整理之前，可能记录 `data/<name>.jsonl`；当前对应定义位于 `data/benchmarks/<name>.jsonl`。历史 manifest 应保持原样，不要为了新目录结构改写既有实验元数据。

## 本地实验约定

- 裸 `evaluate`、`autonomous-benchmark`、dashboard、单次 demo 和 agent 默认都使用 `runs/manual/`，不会覆盖参考快照。
- 自定义实验使用 `runs/<experiment-id>/`，例如 `runs/intern-baseline/`。
- 除上表五个参考快照和本文件外，`runs/` 下的新内容默认被 Git 忽略，避免把临时结果混入提交。
- 复用已有输出目录必须显式传入 `--overwrite`；需要保留证据时应使用新的 experiment id。
- 不要把不同任务集、模型、provider 或防护配置的结果合并到同一目录，也不要直接比较 scripted control 与 provider-backed 结果。
- 真实模型 unittest 可设置 `AGENTGUARD_REAL_MODEL_OUTPUT_ROOT=runs/manual/real-model`；smoke 与 frontier 会分别写入其下的 `smoke/` 和 `frontier/`，CI 也使用这一结构上传脱敏证据。
- Provider 返回 401、402、429 或 5xx 时，本轮属于失败，不应生成或提交“通过”快照；修复凭据、账号权益或限流后使用新的 experiment id 重跑。
