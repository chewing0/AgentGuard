# 模型配置

本目录保存不含密钥的 Provider 配置模板：

- `openai-compatible.example.json`：通用 OpenAI-compatible API。
- `kimi-code.example.json`：Kimi Code 环境。
- `siliconflow-claude-code.example.json`：Claude Code 环境下的 SiliconFlow 路由。

使用时复制为 `*.local.json` 并通过 `api_key_env` 引用环境变量。`configs/*.local.json` 已被 Git 忽略；不要把 API key、Authorization header 或带凭据的 URL 写入任何配置文件。

示例：

```powershell
Copy-Item configs/openai-compatible.example.json configs/openai-compatible.local.json
$env:AGENTGUARD_OPENAI_API_KEY = "<your-key>"
python -m agentguard autonomous-agent --model-config configs/openai-compatible.local.json
```
