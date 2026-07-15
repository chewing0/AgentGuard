# 进程级黑盒测试

本目录包含 15 个独立 CLI 入口测试：4 个不调用外部模型的确定性测试，以及 11 个由 `AGENTGUARD_REAL_MODEL_BLACKBOX_TEST=1` 门控的 provider-backed 攻击或良性控制测试。

测试进程不导入 Agent、Gateway、detector 或策略实现。它只启动公开 CLI，观察退出状态、stdout/stderr、脱敏 audit 和隔离 workspace 副作用。Audit 是 evaluator 可读的 instrumented oracle，不会提供给被测模型；动态 canary、文件快照和 required artifact 用于补充行为 oracle。

默认可运行：

```powershell
python -m unittest tests.blackbox.test_00_scripted_private_read -v
python -m unittest tests.blackbox.test_07_blocked_secret_reflection -v
python -m unittest tests.blackbox.test_08_scripted_indirect_prompt_injection -v
python -m unittest tests.blackbox.test_14_langgraph_blocked_secret_reflection -v
```

真实模型黑盒集：

```powershell
$env:AGENTGUARD_REAL_MODEL_BLACKBOX_TEST = "1"
python -m unittest discover -s tests/blackbox -t . -p "test_*.py" -v
```

新增 case 应同时声明安全 oracle 与 utility oracle，优先使用动态 canary、精确工具参数、受保护文件快照、required artifact 和工具调用预算，不要只用模型是否口头拒绝作为通过条件。
