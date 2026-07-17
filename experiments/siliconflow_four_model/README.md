# SiliconFlow 四模型 Provider 黑盒矩阵

本目录集中保存 GLM-5.1、Kimi-K2.6、MiniMax-M2.5 和 DeepSeek-V4-Pro 的 88-entry 实验定义与统一运行入口。通用调度、预检、错误分类和指标计算仍由 `agentguard/experiment_matrix.py` 提供，本目录只保留该实验专属内容。

```text
siliconflow_four_model/
├─ run_matrix.py                              统一入口，默认只生成计划
├─ siliconflow-four-model-matrix.json         4 模型 × 2 次 × 11 case
├─ siliconflow-glm-5.1.example.json           GLM-5.1 无密钥配置
├─ siliconflow-kimi-k2.6.example.json         Kimi-K2.6 无密钥配置
├─ siliconflow-minimax-m2.5.example.json      MiniMax-M2.5 无密钥配置
└─ siliconflow-deepseek-v4-pro.example.json   DeepSeek-V4-Pro 无密钥配置
```

## 只查看计划

默认不会调用 Provider，也不会创建输出目录：

```powershell
python experiments/siliconflow_four_model/run_matrix.py
```

## 执行真实矩阵

先在当前 shell 设置与目标主机匹配的运行时凭据：

```powershell
$env:ANTHROPIC_BASE_URL = "https://api.siliconflow.cn"
$env:ANTHROPIC_AUTH_TOKEN = "<new-key>"

python experiments/siliconflow_four_model/run_matrix.py `
  --output runs/manual/siliconflow-four-model `
  --execute
```

执行器会逐模型预检；Provider 错误、超时和运行时错误标为无效运行，不进入任务级通过率分母。Provider stdout/stderr 不落盘。复用输出目录必须显式增加 `--overwrite`。

2026-07-17 的脱敏参考结果位于 [`runs/provider_siliconflow_multimodel/`](../../runs/provider_siliconflow_multimodel/)。该结果每模型仅重复 2 次，不能解释为稳定模型排名或纯安全率。
