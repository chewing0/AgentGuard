# AgentGuard：LLM Agent 安全评测与运行时防御

**项目定位：** 研究性实习项目｜**技术栈：** Python、LangGraph/LangChain、SQLite、MCP、Chromium、GitHub Actions

## 主要内容

面向可调用文件、知识库、API 和代码工具的 LLM Agent，研究 prompt injection、工具误用、敏感数据外泄和持久化投毒风险；在 Agent 与工具后端之间构建可审计的执行边界，在副作用发生前完成授权、参数校验、风险检测、人工确认与阻断。

## 主要工作

- 设计统一安全网关，覆盖角色与 scope 授权、工具参数约束、路径/域名白名单、高风险审批及 fail-closed 执行策略。
- 实现提示注入和敏感信息检测、动态 canary/凭据跨步骤追踪、输出脱敏与最终回答防护，并通过哈希链/HMAC 审计支持结果追溯和无执行策略回放。
- 接入 LangGraph Agent loop、MCP stdio、SQLite 跨会话记忆、禁网 Chromium 多通道 observation 守卫和受限表达式子进程沙箱。
- 构建分层评测体系，包括确定性策略回归、冻结留出集、scripted Agent 集成、15 项进程级黑盒测试、真实 Provider gate、外部语料适配器和多模型重复实验矩阵。

## 成果

- 在 35-task、44-step 内部回归中允许 **18/18** 个安全调用；**26/26** 个危险调用均未立即执行，其中 25 个被阻断、1 个进入人工确认。
- 在 15-task LLM 安全 scripted control 中覆盖 13 类攻击，14 个预定危险动作全部进入防护链路，结果为 **13 个阻断、1 个复核、0 个执行、0 个输出泄漏**。
- 建立 **118 项自动化测试**和 GitHub Actions CI；最近一次离线运行 **104 项通过、14 项真实 Provider gate 正常跳过、0 项失败**。
- 完成 GLM-5.1、Kimi-K2.6、MiniMax-M2.5、DeepSeek-V4-Pro 的 **88-entry** Provider 黑盒矩阵；86 次有效运行中 65 次通过，任务级通过率 **0.7558**，并记录 Wilson 95% CI、无效运行、逐 case 脱敏结果和源阶段哈希。

> 结果边界：当前为研究原型；多模型实验每模型仅重复 2 次，任务级通过率同时包含安全与效用，不代表纯安全率、稳定模型排名或生产级防护能力。
