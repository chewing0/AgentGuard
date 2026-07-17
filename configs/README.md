# 模型配置

本目录保存不含密钥的 Provider 配置模板：

- `openai-compatible.example.json`：通用 OpenAI-compatible API。
- `kimi-code.example.json`：Kimi Code 环境。
- `siliconflow-claude-code.example.json`：Claude Code 环境下的 SiliconFlow 路由。
- `experiment-matrix.example.json`：至少两个模型、至少两次重复和完整 11-case Provider 黑盒矩阵的 dry-run 模板。

GLM-5.1、Kimi-K2.6、MiniMax-M2.5、DeepSeek-V4-Pro 的专用配置、88-entry 矩阵和运行入口已集中到 [`experiments/siliconflow_four_model/`](../experiments/siliconflow_four_model/)，不再散放在通用配置目录。

使用时复制为 `*.local.json` 并通过 `api_key_env` 引用环境变量。`configs/*.local.json` 已被 Git 忽略；不要把 API key、Authorization header 或带凭据的 URL 写入任何配置文件。

示例：

```powershell
Copy-Item configs/openai-compatible.example.json configs/openai-compatible.local.json
$env:AGENTGUARD_OPENAI_API_KEY = "<your-key>"
python -m agentguard autonomous-agent --model-config configs/openai-compatible.local.json
```

模型配置可选填写 `input_cost_per_million_usd` 和 `output_cost_per_million_usd`。两项都存在时自治评测才计算估算成本；缺少任一项时保留 token 统计并把成本覆盖标记为不可用。Provider 价格会变化，应只在本地配置中填写经核验且带日期的数值。

矩阵命令默认只打印计划，不调用 Provider：

```powershell
python -m agentguard experiment-matrix `
  --matrix configs/experiment-matrix.example.json `
  --output runs/manual/provider-matrix
```

确认账户、预算、任务版本和输出目录后才添加 `--execute`。执行器会先对每个模型进行一次最小 Provider 预检；任何模型出现鉴权、权限、计费或可用性错误时，矩阵会在运行 case 前整体失败。预检通过后，矩阵执行会丢弃 Provider stdout/stderr，只保留每个 case 的脱敏 outcome、Provider HTTP 状态、返回码、时延和聚合置信区间。Provider 错误、超时和运行时错误会标为 `invalid` 并继续后续 case，不进入任务级通过率和 Wilson 区间分母；效用失败仍是有效失败，因此该指标不能称为纯安全通过率。

四模型矩阵：

```powershell
python experiments/siliconflow_four_model/run_matrix.py `
  --output runs/manual/siliconflow-four-model `
  --execute
```

该命令会产生真实 Provider 调用。运行前必须在当前 shell 同时设置 `ANTHROPIC_BASE_URL=https://api.siliconflow.cn` 和 `ANTHROPIC_AUTH_TOKEN`，并确认四个模型 ID 对账户可用；运行时会校验二者与配置主机一致，防止把其他 Provider 的 token 发给 SiliconFlow。不要把 token 写进 JSON。

2026-07-17 的实际四模型结果保存在 [`runs/provider_siliconflow_multimodel/`](../runs/provider_siliconflow_multimodel/)：88 次计划中 86 次有效、65 次通过、21 次任务失败、2 次无效。该快照只有每模型 2 次重复、来自 dirty worktree，且旧阶段失败无法全部区分安全与效用原因，只能作为初步研究证据。

GitHub Actions 中的 `siliconflow-four-model-matrix` job 默认关闭。需要在仓库中创建 Secret `SILICONFLOW_ANTHROPIC_AUTH_TOKEN`，并仅在确认预算后把 Variable `AGENTGUARD_RUN_SILICONFLOW_MATRIX` 设为 `1`。工作流不会读取聊天记录、配置文件或普通仓库变量中的密钥。
