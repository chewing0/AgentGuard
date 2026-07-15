# 测试目录

测试按可见性边界分为两组：

- `non_blackbox/`：单元、组件、LangGraph 集成、评估与 Provider gate 测试；共享实现位于 `non_blackbox/suites/`。
- `blackbox/`：只通过公开 CLI 子进程观察输出、审计和隔离 workspace 副作用的进程级测试。
- `real_model_support.py`：两组测试共用的真实模型配置、门控与错误脱敏 helper。

运行全部测试：

```powershell
python -m unittest discover -s tests -v
```

运行默认黑盒集或非黑盒集：

```powershell
python -m unittest discover -s tests/blackbox -t . -p "test_*.py" -v
python -m unittest discover -s tests/non_blackbox -t . -p "test_*.py" -v
```

真实模型入口默认跳过。开启前请阅读各子目录 README、`docs/quickstart.md` 与 `SECURITY.md`，并使用合成数据和隔离 workspace。
