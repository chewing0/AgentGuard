# AgentGuard 文档导航

`docs/` 保存面向使用者、研究者、实习生和项目展示的专题文档。根目录 [README](../README.md) 只负责项目概览；具体操作和研究细节以本目录文档为准。

## 按目标阅读

| 你的目标 | 建议入口 | 读完后应能完成 |
|---|---|---|
| 第一次运行项目 | [新人上手指南](quickstart.md) | 安装环境、运行 99 项测试、复现攻击拦截并生成 dashboard |
| 设计或复核安全实验 | [研究与实验指南](research_guide.md) | 说明威胁模型、攻击矩阵、评测语义、当前证据和有效性威胁 |
| 安排阶段性实践 | [LLM 安全实习路线](internship_roadmap.md) | 按 0+6 周计划交付攻击、防御、评测和实验结果 |
| 准备简历或面试 | [简历展示版](resume_showcase.md) | 使用准确措辞介绍贡献、结果和边界 |

推荐新人按以下顺序阅读：

1. 根目录 [README](../README.md)
2. [新人上手指南](quickstart.md)
3. [研究与实验指南](research_guide.md)
4. 根据目标选择 [实习路线](internship_roadmap.md) 或 [简历展示版](resume_showcase.md)

## 文档职责

- `quickstart.md` 只维护可执行命令、预期输出、目录约定和常见问题。
- `research_guide.md` 是威胁模型、攻击分类、防御逻辑、评测方法、结果和研究局限的唯一主文档。
- `internship_roadmap.md` 只维护学习顺序、周任务、交付物和验收标准。
- `resume_showcase.md` 只维护对外展示措辞、图表资产和面试讲解重点。
- `assets/` 保存架构和结果 SVG；图中的指标必须与研究指南明确对应。

原先分散的系统设计、风险分类、实验报告、演示指南和差距分析已合并到 `quickstart.md` 与 `research_guide.md`，不再维护重复版本。

## 目录级说明

项目的结构化数据、配置、测试和结果各有独立索引：

| 目录 | 说明 |
|---|---|
| [`configs/`](../configs/README.md) | Provider 模板、本地配置和密钥约定 |
| [`data/`](../data/README.md) | 合成 workspace、工具策略与数据边界 |
| [`data/benchmarks/`](../data/benchmarks/README.md) | Benchmark、Provider profile 和黑盒 case |
| [`tests/`](../tests/README.md) | 测试分层与运行方式 |
| [`tests/blackbox/`](../tests/blackbox/README.md) | 公开 CLI 黑盒 oracle 和真实模型 gate |
| [`tests/non_blackbox/`](../tests/non_blackbox/README.md) | 单元、组件、集成与评估测试 |
| [`runs/`](../runs/README.md) | 参考快照、本地输出和历史 manifest 约定 |

## 维护约定

- 路径以当前结构为准：任务定义位于 `data/benchmarks/`，本地输出位于 `runs/manual/`。
- 新增命令优先写入 `quickstart.md`；新增研究结论优先写入 `research_guide.md`，根 README 只保留摘要和链接。
- 更新任务数量、测试数量或实验结果时，同时核对根 README、quickstart、research guide 和相关目录 README。
- 历史 `runs/*/manifest.json` 是不可变实验元数据，即使目录后来调整，也不要改写其中记录的旧输入路径。
- Provider 单次运行必须标注模型、日期、`n`、失败案例和不可外推边界。
