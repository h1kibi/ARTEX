# ARTEX 施工记录（11-24）

- 状态：已实施
- 依据：`docs/ARTEX-施工方案-11-24.md`
- 范围：Go 后端、PostgreSQL schema、任务详情前端

## 1. 已实现

### 1.1 Information 类型

- `record_fact` 新增 `fact_type`：`observation / claim / hypothesis / decision / finding_candidate`。
- 写入校验：
  - observation 必须有 activity 或 evidence 引用；
  - claim 必须有 observation、activity 或 evidence 引用，并标注 confidence；
  - hypothesis 必须有支撑引用、`validation_actions` 和合法状态；
  - decision 必须引用 claim/hypothesis，并给出下一意图或 checkpoint；
  - finding_candidate 只能是 `pending / rejected`，不能写 confirmed。
- 未提供来源时，系统自动挂当前意图最近一条 `tool_result` 作为 provenance。
- 历史 fact 缺少 `fact_type` 时读取为 `legacy_unknown`，不回写、不自动推断。

### 1.2 Route 和 Checkpoint

- 新意图的 `route_id` 等于自身 id；`continuation_of` 继承同一 route、剩余预算和最近 checkpoint。
- Intent payload 增加 `objective / phase / expected_evidence / success_condition / budget / checkpoint_fact_id / route_budget_used`。
- Worker Run 结束（正常、暂停、取消、Watchdog 终止、任务超时）时写入 `fact_type=checkpoint` fact：
  - confirmed claim、open hypothesis、finding、evidence refs；
  - attempted actions、next actions；
  - 当前 run 的工具调用、token、墙钟和累计 route 预算；
  - `run_id`、`created_by_run`、`settlement_reason`。
- Checkpoint 的写入和 `intent -> checkpoint` 边在同一事务；intent 的 `checkpoint_fact_id` 与累计预算同步回写。

### 1.3 ProgressEvent 和预算

- RunMonitor 增加工具调用、token、重复动作、高价值进展、route 预算基线。
- 普通 observation/claim/asset 只记录 `LastOutputAt`；`validated_weakness`、`credential_obtained`、`privilege_change`、`lateral_progress`、`objective_milestone`、`finding_written`、`cleanup_completed` 才重置观察周期。
- `duplicate_action` 记录但不重置周期。
- Watchdog Fast Path 读取 route 预算，工具调用、输入 token 或墙钟超限时走 Settlement 结束，后续由 Planner 用 `continuation_of` 继续。
- Slow Path 快照增加 route、checkpoint、预算、ProgressEvent、finding_candidate 和重复动作摘要。

### 1.4 Cold Digest 保护

- active Route 的 checkpoint 及其引用的 claim/hypothesis/finding 保持 hot。
- settled Route 的 checkpoint 可以进入 digest；digest payload 保留 `checkpoint_id`、`route_id`、`evidence_refs`。
- `CancelIntent` 保护被 checkpoint/candidate/decision 引用的节点，不随意图物理删除。

### 1.5 Finding Candidate

- Worker Run 结束且没有确认 finding 时，把本次 claim/hypothesis 合并为一条 `finding_candidate`（pending）。
- 同一 intent 复用已有 candidate，不重复膨胀。
- 确认漏洞仍只通过 `report_finding` 写入 `findings` 表；candidate 不会自动升级为 confirmed。

### 1.6 查询视图和前端

- 新增：
  - `GET /api/tasks/{id}/routes`
  - `GET /api/tasks/{id}/information`
  - `GET /api/tasks/{id}/evidence`
- 任务详情新增「情报」页：
  - 路线列表与详情（阶段、目标、预算、checkpoint、证据、finding）；
  - Information Graph（observation/claim/hypothesis/decision/candidate/finding 过滤与展开）；
  - Evidence Layer（引用、类型、可用性、来源节点）。
- 资产覆盖图抽屉增加关联路线。
- 修复任务详情「最近活动」始终为空的问题。

### 1.7 工作区与构建

- `data/` 自动生成嵌套 `go.mod`，运行时工作区不再被父模块的 `go build ./...` / `go test ./...` 扫描。

### 1.8 三图交接补强（同日第二轮）

- **预算 handoff**：`add_intent` 接续时合并原路线预算（新维度非零才覆盖），并从最新 checkpoint 读取累计用量；工具调用 / 输入 token / 墙钟任一耗尽时，拒绝不带更大 `budget` 的接续，错误信息给出已用量与下限。
- **Checkpoint 原子性**：新增 `ExplorationStore.SaveRunCheckpoint`，checkpoint fact、`intent -> checkpoint` 边、前一 checkpoint 血缘、intent 的 `checkpoint_fact_id/route_budget_used` 在同一事务提交。
- **Candidate 对账**：`rejected/confirmed/expired` 候选不被重开；支持 hypothesis-only 候选；只有存在的关联键才写入 payload。
- **查询视图**：`/information` 使用 SQL 全图计数 + 分页，支持 `include_sources=1`；`/evidence`、`/routes` 的 DB 错误返回 500；Route 状态按 running/open/paused/done/blocked/exhausted/stopped/superseded 投影，空数组不输出 `null`。
- **引用过滤**：`record_fact`/`report_finding` 校验 activity/node/finding 存在性；artifact 必须在任务工作目录内且文件存在；继承数据按 `valid_until`、`sensitivity`、`inheritance_policy` 过滤。

### 1.9 合入前收口（同日第三轮）

- **Route 终态**：`/routes` 由最新非删除意图决定状态；`I1(done) -> I2(exhausted/blocked/stopped)` 不再整体显示 `succeeded`。
- **重跑预算**：单条与批量 rerun 复用 `db.RouteBudgetExhausted`，路线预算耗尽时返回 409，并提示使用扩容的 `continuation_of`。
- **artifact 软链**：根目录与目标均 `EvalSymlinks` 后再做前缀校验，阻止 Worker 用符号链接读取工作目录外的文件。
- **迁移键**：`tool_schema_refresh_v9_information_refs`、`planner_prompt_route_handoff_v4_budget_expansion`，确保存量库拿到二轮 schema/提示词。
- **仓库卫生**：`.gitignore` 增加 `/artex-dev-*.exe`，本地多版本二进制不再混入未跟踪列表。

### 1.10 运行时闭环（同日第四轮）

- **续跑 Worker 交接**：`renderPriorCheckpoint` 把前序 checkpoint 的结论、confirmed claim、open hypothesis、attempted_actions、next_actions、evidence refs 和累计用量内联进 Worker 系统提示；Planner 的 checkpoint 摘要与 Watchdog 快照也补上 attempted_actions。
- **ProgressEvent**：Worker 提示词明确 progress_event 取值与触发时机；收尾提示词要求用 `next_actions` / `validation_actions` 交接未完成方向。
- **预算兜底**：新路线未填 budget 时默认 240 次工具调用 / 120 万输入 token；Run 结束写回 checkpoint 后，即使 Watchdog 关闭，累计预算耗尽也会把意图标记为 `exhausted`（`routeBudgetTerminalState`）。
- **Evidence 绑定**：`/evidence` 合并 `finding_traffic_bindings` 的 traffic id、evidence version、snapshot id；前端显示版本。
- **长运行/概览**：checkpoint 活动分页读取；`graph_overview` 的 facts/recent_facts 排除 checkpoint 与 origin fact。

### 1.11 合入前复审修复（同日第五轮）

- **继承边界**：`/api/exploration/graph` 来源 fact 与 `expand_digest` 关联成员按 `CanInheritFact` 过滤；关联 digest 正文不跨任务展开。
- **统计口径**：checkpoint 不再进入重跑输出的 `next_actions/evidence`、`yield_count` 或 `FactsYielded`；`list_facts.total` 先过滤继承再计数；任务详情回填持久化最近活动。
- **意图入口**：种子、漏洞跟进、无 LLM 注入意图补 `route_id/phase/default budget`；`RouteIDsForAsset` 兼容隐式 route id。
- **重试预算**：`retry_work` 自动重试也校验路线累计预算。
- **前端**：情报页分接口错误态 + 重试、服务端过滤、任务切换重置、仅轮询当前页签；路线状态复用全局 `StatusBadge`；checkpoint 在播报/探索图单独渲染；finding 计数为 0 时不显示筛选。
- **决策替代方向**：`record_fact.alternatives_rejected` 写入与展示。
- **工程卫生**：`.gitattributes` 统一 LF；11-24 三份文档取消忽略。

## 2. 迁移和兼容

- `tool_schema_refresh_v8_information_route`：一次性刷新 `record_fact`、`add_intent`、`report_finding` 的 schema，保留工具绑定和启停状态。
- 二轮升级：schema 刷新键升至 `tool_schema_refresh_v9_information_refs`（补 `sensitivity/inheritance_policy`），planner 提示词键升至 `planner_prompt_route_handoff_v4_budget_expansion`（预算耗尽接续需显式扩容）。
- 四轮升级：schema 键 `tool_schema_refresh_v11_decision_alternatives`；planner `planner_prompt_route_handoff_v5_default_budget`；worker `worker_prompt_information_types_v7_decision_alternatives`；watchdog `watchdog_prompt_route_budget_v2_attempted`。
- planner / worker / watchdog 提示词追加新默认版本，旧版本保留在 `agent_prompts` 历史中。
- 旧 fact、旧 intent、旧 activity、旧 checkpoint 缺失字段时按现有数据读取，不重写。

## 3. 验证

本轮（补强后）在本地 Docker PostgreSQL（`127.0.0.1:15432`）实际执行，未跳过 PG 用例：

```bash
go build ./...
go vet ./agent/... ./db/... ./server/...
ARTEX_PG_DSN='postgres://artex:***@127.0.0.1:15432/artex?sslmode=disable' \
  go test ./agent ./db ./server -count=1
```

结果：通过（agent 15.8s / db 51.3s / server 146.3s）。

覆盖到的新增回归：

- `TestAddIntentInheritsRouteAndCheckpointBudget`：预算继承、耗尽拒绝、显式扩容；
- `TestRecordFactValidatesInformationTypes`：artifact 存在性/路径穿越/软链逃逸、引用校验；
- `TestRunCheckpointAndCandidateReconciliation`：checkpoint 事务、rejected 候选保护、hypothesis-only 候选；
- `TestRouteInformationEvidenceViews`：空数组序列化、Route 状态机（含 I1(done)→I2(exhausted) 多阶段终态）、Information 计数与 Evidence 视图；
- `TestRouteBudgetTerminalStateWithoutWatchdog`：预算耗尽在无 Watchdog 时也把 done 降级为 exhausted；
- `TestRerunExhaustedRouteRejected`：路线预算耗尽时人工重跑返回 409 且意图保持 exhausted；
- `TestAddIntentDefaultsRouteBudget`：新路线默认预算、接续继承、显式预算覆盖；
- `TestRenderPriorCheckpointHandoff`：续跑 Worker 提示包含结论、attempted_actions、next_actions、证据与 node_detail；
- `TestFindingTrafficAPIAndExport`：`/evidence` 合并 finding_traffic_bindings 并带版本/快照；
- `TestGraphOverviewExcludesCheckpointsFromFacts`：facts/recent_facts 排除 checkpoint 与 origin，checkpoint 仍单独展示并带 attempted_actions；
- `TestRealWorkerAutoAdvanceWriteAndResume`：真实 Worker/SDK/Engine 路径的 artifact 取证与 Watchdog 推进。

第四轮收口后再次执行：

```bash
go build ./...
ARTEX_PG_DSN='postgres://artex:***@127.0.0.1:15432/artex?sslmode=disable' \
  go test ./agent ./db ./server -count=1
```

结果：通过（agent 13.2s / db 46.5s / server 143.4s）。

前端：

```bash
cd web
npx tsc --noEmit -p tsconfig.json
NEXT_EXPORT=1 npx next build --webpack
```

结果：通过。任务详情「情报」页在 mock 数据下完成浏览器检查：路线列表/详情、状态标签、finding 的证据引用与「2 条流量」绑定计数均正常渲染。

本地运行态（已重启）：

- `artex-dev.exe` 已用 `-tags embedui` 重编（前端静态产物来自 `web/out`），监听 `:8787`，流量代理 `:8788`。
- 迁移已落库：`tool_schema_refresh_v10_route_defaults=true`、`planner_prompt_route_handoff_v5_default_budget=true`、`worker_prompt_information_types_v6_progress_handoff=true`、`watchdog_prompt_route_budget_v2_attempted=true`；`tools.add_intent` 的 budget 描述已含默认 240，planner/worker/watchdog 最新提示词分别包含默认预算、progress_event、attempted_actions。
- `:5173` dev server 已改为真实反代（`/api/* -> :8787`），`/api/setup/status` 与 `/api/tasks` 均返回后端一致的 401，不再命中 mock；已登录任务点检需使用现有浏览器会话。

## 4. 未执行或保留

- 任务 #3276 的真实 trace 回放未执行：本机没有可用的目标环境和原始模型调用，无法在本轮离线复现。相关指标仍由新增的 checkpoint、ProgressEvent 和 Slow Path 快照记录，可在真实任务中回放。
- Route 预算只在 Watchdog 开启时由 Fast Path 强制执行；未开启时仍会记录 checkpoint 和累计用量，但不主动终止运行。
- `artifact:` 引用在 agent 侧按当前任务工作目录校验存在性；未设置 artifact roots 的单元测试仍只做格式校验。`traffic:` 引用在流量记录可用时校验 exchange id 是否存在。
- Candidate 对账不自动确认漏洞；确认仍由模型调用 `report_finding` 或人工操作完成。
