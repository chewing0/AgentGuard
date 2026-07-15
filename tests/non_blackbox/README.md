# 非黑盒测试目录

这里保存 84 个单元、组件、框架集成、评估和 Provider 门控测试。83 个业务测试各有一个 `test_*.py` 入口文件；另有 1 个目录契约测试保证入口与共享实现严格一一对应。复用的 setup、fixture 和断言实现集中在 `suites/`，避免为一测试一文件复制大量代码。

| 目录 | 数量 | 内容 |
|---|---:|---|
| `core/` | 32 | Gateway、审计、敏感数据、模型配置和目录契约 |
| `agent/` | 15 | Demo/SOC Agent、LangGraph adapter 和自主 Agent loop |
| `evaluation/` | 23 | Benchmark loader、评分、指标和 run manifest |
| `cli/` | 3 | CLI 失败状态和异常信息脱敏 |
| `provider/` | 11 | 3 个真实模型 Agent gate 和 8 个 Provider 配置/错误处理测试 |
| **合计** | **84** | 不包含 `tests/blackbox/` 的 15 个进程级黑盒测试 |

运行全部非黑盒测试：

```powershell
python -m unittest discover -s tests/non_blackbox -t . -p "test_*.py" -v
```

`suites/` 不是独立测试入口，不应直接用于完整测试发现。需要单独运行某项时，直接运行其所属目录下的 `test_*.py` 模块。

每个入口也可以作为模块单独运行，例如：

```powershell
python -m tests.non_blackbox.core.test_gateway_allows_public_file_read
```
