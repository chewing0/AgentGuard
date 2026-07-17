# 实验目录

`experiments/` 保存需要成组复现的专用实验入口与无密钥配置。通用实现保留在 `agentguard/`，不可变输入保留在 `data/benchmarks/`，运行结果写入 `runs/`。

| 目录 | 内容 |
|---|---|
| [`siliconflow_four_model/`](siliconflow_four_model/README.md) | GLM-5.1、Kimi-K2.6、MiniMax-M2.5、DeepSeek-V4-Pro 的 4 × 2 × 11 Provider 黑盒矩阵 |

实验目录不得保存 API key、Authorization header、生产数据或运行生成的 workspace。运行时凭据只能通过环境变量提供。
