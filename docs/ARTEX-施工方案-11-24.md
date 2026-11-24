# ARTEX 施工方案（11-24）

- 状态：施工设计稿
- 适用范围：真实 Red Team / Pentest 自治测试能力
- 当前状态：只读设计；本方案编写过程未修改 ARTEX 代码、数据库、配置和前端
- 目标读者：负责实施、测试、集成和复核的 Agent
- 设计依据：
  - `docs/guideline.md`
  - `docs/ARTEX-优化方案.md`
  - `README.md`
  - `docs/ARTEX-Watchdog优化方案-11-19.md`
  - `docs/ARTEX-Watchdog优化施工方案-11-19.md`
  - 当前 `server`、`agent`、`db`、`evidence`、`traffic` 和 `third_party/norma` 实现

## 1. 施工原则

### 1.1 复用现有模块

施工必须继续使用以下现有模块：

- `Manager`、`Task`、`Engine`；
- `Planner`、`Worker`、`MainAgent`；
- `RunMonitor`、Watchdog Fast Path、Slow Path；
- `Settlement`、`RequestSettlement`、`terminalreason.go`；
- `exploration_nodes`、`exploration_edges`、`exploration_anchors`；
- `assets`、`task_scope`、`company_scope`；
- `activity`、transcript、trace 工具；
- traffic、`evidence.Store`、traffic bindings、snapshots；
- `findings`、reporter、retester；
- `coldgraph.go`、digest、Norma Compaction、NOA、tool output spill；
- `steer_work`、`retry_work`、peer request 和 arbitration。

施工 Agent 不得创建以下平行模块：

- 全局 Router LLM；
- 平行 Memory Store；
- 平行 Evidence Store；
- 新消息总线；
- 新 Watchdog 状态机；
- 未经验证的独立 Operation 数据库层。

### 1.2 先建立可验证语义

每个阶段先确定：

- 输入数据来自哪里；
- 输出写入哪个现有对象；
- 状态如何迁移；
- 失败如何恢复；
- 原始 Evidence 如何回查；
- 现有 cold digest 是否会影响它。

只有现有对象无法满足查询、事务或恢复要求时，才增加字段或表。

### 1.3 保持旧数据可读

历史任务中的旧 fact、旧 Intent payload、旧 activity 和旧 finding 必须继续可读。

旧数据无法可靠分类时标记为：

```text
legacy_unknown
```

不得根据模型猜测把旧 fact 自动改成 Observation、Claim 或 confirmed Finding。

### 1.4 先完成阶段验证再进入下一阶段

每个阶段必须完成：

- 代码审查；
- 真实 PostgreSQL 测试；
- 状态竞争测试；
- 相关 trace 回放；
- 迁移或兼容性检查；
- 集成负责人复核。

施工 Agent 不在其他 Agent 正在修改的文件上工作。每个工作包先读取当前文件和相关测试，再开始修改。

## 2. 当前项目实现和现状

### 2.1 系统分层

当前系统分层如下：

```text
Manager
  -> Task / Exploration Store
  -> Engine
    -> Planner Loop
    -> Worker Loop x N
    -> RunMonitor / Watchdog
  -> PostgreSQL
    -> Asset Graph
    -> Exploration Graph
    -> Activity / Worker Runs
  -> Traffic / Evidence / Guard / Intercept / Enrich
```

`README.md` 已经定义：

- Asset Graph 是跨任务共享的资产真值库；
- Exploration Graph 是每任务独立的目标、Intent、fact、finding 和 hint 图；
- `exploration_anchors` 连接两张图；
- Engine 负责 Planner、Worker、暂停、截止时间和 drain；
- Watchdog 独立观察运行状态。

### 2.2 Engine 和 Worker 生命周期

[server/engine.go](../server/engine.go) 当前流程：

```text
workerLoop
  -> claimNext
  -> runIntent
  -> 生成 run_id
  -> RunMonitor.Register
  -> Worker.Execute
  -> Settlement / retry / pause / kill / timeout
  -> Intent 状态迁移
  -> RunMonitor.Finish
  -> 唤醒 Planner
```

Intent 当前状态包括：

```text
open
running
paused
done
blocked
exhausted
stopped
deleted
```

现有 `runIntent` 已经统一处理：

- Worker 执行；
- Provider 错误重试；
- Watchdog Settlement；
- pause、cancel、kill；
- Intent 终态；
- Worker 时长；
- Planner 通知。

后续阶段必须继续使用 `runIntent`，不得另建第二条 Worker 结束路径。

### 2.3 当前 Watchdog

当前 Watchdog 由以下模块组成：

- `server/watchdog_config.go`：配置和周期来源；
- `server/watchdog_monitor.go`：运行状态、心跳、phase、cycle；
- `server/watchdog_fast.go`：pressure、Slow Path 入队、周期处理；
- `server/watchdog_service.go`：Slow Path Agent；
- `server/watchdog_terminate.go`：终止和 Settlement；
- `server/watchdog_runtime.go`：运行结束清理；
- `server/watchdog_peer.go`：Worker 间资源请求；
- `server/watchdog_arbitration.go`：资源仲裁；
- `db/watchdog.go`：`worker_runs`、`watchdog_jobs`、`watchdog_requests` 读写；
- `agent/watchdog.go`：只读 JSON 判断 Agent。

当前配置语义：

```text
watchdog_enabled=false（默认）
worker.run_seconds=1200（周期来源）
watchdog_pressure_after_sec=480
watchdog_slow_path_after_sec=600
watchdog_max_auto_cycles=2
```

Watchdog 开启后，`server/task_llm.go` 将 Worker SDK `MaxDuration` 设为 0，`run_seconds` 表示周期长度。施工必须保留这一兼容语义，同时增加独立的 Path/Run 预算，避免周期成为无限延长的唯一控制机制。

### 2.4 当前上下文机制

Worker 已经使用 Norma 内置 Compaction：

- `agent/worker.go` 设置 `Compaction`；
- `agent/provider.go` 默认 context window 为 200K；
- Norma 在每个模型回合前执行 MicroCompact 和 AutoCompact；
- tool output 超过限制时写入 `cmd-output`；
- NOA 是关闭状态的实验路径；
- `agent/compaction.go` 维护探索图 cold digest。

这些机制继续保留。Checkpoint/Handoff 用于阶段交接，Compaction 用于单一连续阶段的上下文维护。

### 2.5 当前证据和 Finding

当前 `evidence.Store` 主要负责：

- traffic request/response body；
- 内容寻址和 SHA-256；
- staging 和 durable write；
- traffic snapshot；
- finding traffic binding；
- evidence version。

命令输出、文件和普通 artifact 还可能保存在：

- `activity.detail`；
- `data/tasks/...`；
- `cmd-output`；
- transcript；
- 工具工作目录。

施工时将它们统称为 Evidence Layer，但不得假设它们都已经具备 `evidence.Store` 的完整内容寻址和清理能力。

## 3. 目标数据模型

## 3.1 Asset Graph

继续使用：

- `assets`；
- `companies`；
- `company_scope`；
- `task_scope`；
- `exploration_anchors`。

Asset Graph 只记录：

- 资产身份；
- 资产拓扑；
- 当前资产视图；
- scope；
- 来源和最近观察时间。

Asset Graph 不记录：

- 完整攻击推理；
- Worker transcript；
- Task 特定 Decision；
- 未验证的模型判断。

资产身份与资产观察必须分离：

```text
identity
observation
validity
provenance
scope
```

### 3.1.1 资产观察写入

Worker 写入资产时继续使用现有 `insert_assets` 和 Asset Store。后续需要让资产观察保留：

- `task_id`；
- `intent_id` 或 owner node；
- 观察时间；
- 来源 activity 或 evidence 引用；
- 可选有效期；
- 当前状态。

优先使用现有 `assets.extra`、`task_ids`、`exploration_anchors` 和 activity metadata。只有当前字段无法查询观察来源时，才增加字段。

## 3.2 Route Graph

Route Graph 是当前 Task/Exploration 中的攻击路径视图。

它使用：

- `exploration_nodes`；
- `exploration_edges`；
- Intent payload；
- `continuation_of`；
- `exploration_anchors`；
- `worker_runs`；
- Checkpoint fact。

### 3.2.1 Route ID

一个攻击路径可以跨多个 Intent 和 Worker Run。Route ID 不能等同于每个 Intent ID。

规则：

```text
首个路线 Intent 的 ID = route_id
continuation Intent 继承同一个 route_id
每个 Intent 保留自己的 intent_id
每个 Worker Run 保留自己的 run_id
```

示例：

```text
route_id R1
  ├── intent_id I1
  │     ├── run_id W1
  │     └── checkpoint C1
  ├── intent_id I2
  │     └── run_id W2
  └── intent_id I3
        └── run_id W3
```

`continuation_of` 继续表示相邻 Intent 的来源，不能单独承担 Route 身份。

初期 `route_id` 放入 Intent payload，由运行时生成和继承。模型提供的 `route_id` 不直接信任，运行时以来源 Intent 和当前 Exploration 校验。

### 3.2.2 Route payload

```json
{
  "route_id": 101,
  "route_kind": "path_stage",
  "objective": "验证对象级授权边界",
  "phase": "validation",
  "asset_ids": [12],
  "parent_intent_id": 55,
  "checkpoint_fact_id": 1010,
  "expected_evidence": ["不同用户对象的响应差异"],
  "success_condition": "确认跨用户读取或排除该假设",
  "budget": {
    "max_tool_calls": 60,
    "max_input_tokens": 120000
  }
}
```

### 3.2.3 Route 阶段

阶段使用 Intent payload 和 Checkpoint 表达：

```text
recon
validation
exploitation
privilege
lateral
objective
verification
evidence
cleanup
```

阶段迁移必须有 Evidence 或 Claim 引用：

```text
阶段成功条件满足
  -> 写入 Checkpoint
  -> Planner 选择下一阶段
```

### 3.2.4 Route 状态

使用现有 Intent 状态承载运行状态，payload 补充 Route 语义：

```text
proposed
active
blocked
succeeded
failed
superseded
paused
```

不新增另一套并行状态机。

## 3.3 Information Graph

Information Graph 是现有 facts、activity、findings 和来源关系的逻辑视图。它可以跨任务查询，但默认按 Task、来源、时间和敏感性过滤。

语义链：

```text
Observation
  -> Claim
    -> Hypothesis
      -> Decision
        -> Finding
```

### 3.3.1 Observation

Observation 必须来自可回查来源：

- 工具结果；
- HTTP 请求和响应；
- traffic；
- 文件内容；
- 进程或系统状态；
- 服务端错误；
- 任务平台响应；
- 其他环境反馈。

模型文字不能单独创建 Observation。

### 3.3.2 Claim

Claim 是对 Observation 的结构化归纳。使用现有 `fact` 节点：

```json
{
  "fact_type": "claim",
  "summary": "未认证请求可以读取用户列表",
  "confidence": "observed",
  "evidence_refs": ["traffic:123"],
  "source_activity_ids": [456, 457],
  "observed_at": "...",
  "valid_until": "..."
}
```

### 3.3.3 Hypothesis

Hypothesis 是模型或 Planner 的待验证假设：

```json
{
  "fact_type": "hypothesis",
  "summary": "该接口可能存在对象级授权缺失",
  "claim_ids": [101],
  "validation_actions": ["使用不同用户对象进行授权边界验证"],
  "state": "open",
  "confidence": "medium"
}
```

状态：

```text
open
supported
rejected
expired
```

Hypothesis 不能直接作为 confirmed Claim 或 Finding。

### 3.3.4 Decision

Decision 记录 Planner、Worker 或 Watchdog 的选择，不表示环境事实。

来源位置固定：

| Decision | 主要保存位置 |
| --- | --- |
| Route 选择 | Intent payload |
| 阶段转移 | Checkpoint fact payload |
| Watchdog 判断 | Watchdog activity 和审计记录 |
| 临时模型判断 | transcript/activity，不进入长期 Information Graph |

Decision 必须引用支撑 Claim/Hypothesis、被放弃的替代方向和下一步 Intent。

### 3.3.5 Finding

Finding 是有可复现 Evidence 的安全问题。Finding 必须有：

- 明确目标；
- 复现请求、响应或命令输出；
- 真实影响；
- Evidence 引用；
- 资产引用；
- 产生 Finding 的 Intent；
- 报告和复测状态。

## 3.4 Information 写入不变量

现有 `record_fact` 继续作为统一入口，但入口必须根据 `fact_type` 校验必要字段：

| 类型 | 必要条件 |
| --- | --- |
| `observation` | activity、traffic 或 artifact 至少一个来源 |
| `claim` | Observation 或 Evidence 至少一个引用 |
| `hypothesis` | 支撑引用、验证动作和状态 |
| `decision` | 支撑 Claim/Hypothesis、下一步 Intent 或 Checkpoint 引用 |
| `checkpoint` | Intent、Run、phase、预算和下一步 |
| `finding_candidate` | Claim/Evidence 引用，验证状态未完成 |
| `legacy_unknown` | 历史数据无法可靠分类时使用 |

旧 fact 不自动推断类型。

## 3.5 Evidence Layer

Evidence Layer 是逻辑层，当前 `evidence.Store` 是其中的 traffic evidence 物理实现。

### 当前 `evidence.Store` 已提供

- traffic request/response body；
- 内容寻址；
- SHA-256；
- staging 和 durable write；
- traffic snapshots；
- finding traffic binding；
- evidence version。

### 其他证据来源

命令输出、文件和 artifact 当前可能位于：

- `activity.detail`；
- `data/tasks/...`；
- `cmd-output`；
- transcript；
- 工具工作目录。

文档和实现不得把这些来源描述为已经具备相同的 hash、staging 和清理保证。

### Evidence 不变量

- 原始证据只追加，不覆盖；
- Evidence 有稳定引用、来源和时间；
- Finding 必须引用可回查 Evidence；
- Checkpoint 只保存 Evidence 引用和摘要；
- 图压缩不能删除仍被 Finding 或 active Checkpoint 引用的 Evidence；
- Evidence 原文不能被摘要替换；
- Evidence 必须可以追溯到 activity、traffic、artifact 或其他审计记录。

## 4. 数据来源、继承和有效性

当前不引入独立 `Engagement` 对象。Information Graph 使用 Task 和 direct source task 关系表达范围。

全局查询必须经过：

```text
source_task_id
observed_at
valid_until
sensitivity
inheritance_policy
```

继续使用 `exploration_sources.go`：

- 直接来源任务只读；
- 继承节点保留 `Inherited` 和 `SourceTaskID`；
- 不自动展开间接来源；
- 进入当前 Worker 或 Planner 上下文前经过来源和有效期过滤。

### 可以继承

- 稳定资产身份；
- 已验证的服务技术；
- 明确版本条件下的代码或配置结论；
- 有效期明确的资产关系；
- 已验证的安全控制状态。

### 默认不能继承

- 凭据；
- session token；
- 临时端口状态；
- 内部文件内容；
- 用户数据；
- 未验证 Hypothesis；
- 模型 Decision；
- Task 特定授权判断。

## 5. Checkpoint、Worker Run 和 Handoff

### 5.1 Worker Run

复用 `run_id`、`worker_runs`、RunMonitor 和 activity。需要表达：

```text
run_id
intent_id
route_id
phase
started_at
cycle_start
last_event_at
last_output_at
last_high_value_progress_at
tool_calls
input_tokens
output_tokens
settlement_state
checkpoint_fact_id
```

先从 activity result usage、RunMonitor 和 Intent payload 聚合。只有聚合不能提供稳定结果时，才增加字段。

### 5.2 Checkpoint

Checkpoint 使用 fact 节点：

```json
{
  "fact_type": "checkpoint",
  "route_id": 101,
  "intent_id": 102,
  "run_id": "run-...",
  "path_phase": "validation",
  "summary": "已确认未认证读取，尚未确认对象级授权",
  "confirmed_claim_ids": [1010],
  "open_hypothesis_ids": [1011],
  "evidence_refs": ["traffic:123", "artifact:456"],
  "finding_ids": [],
  "attempted_actions": ["GET /admin", "GET /admin?id=2"],
  "next_actions": ["验证不同用户对象读取边界"],
  "budget_used": {
    "tool_calls": 18,
    "input_tokens": 42000
  },
  "created_by_run": "run-..."
}
```

### 5.3 Handoff

Worker Run 到达预算或 Watchdog 请求切换时：

```text
停止新的高成本动作
  -> 保存 Claim、Hypothesis 和 Evidence 引用
  -> 记录下一步和预算使用
  -> 进入 Settlement
  -> 写入 Checkpoint
  -> 结束当前 Run
  -> Planner 使用 continuation_of 创建下一阶段
```

新的 Run 继承同一 `route_id` 和剩余预算，不恢复完整预算。

### 5.4 Checkpoint 压缩保护

当前 `coldgraph.go` 允许 settled Intent 和 fact 进入冷区。需要增加以下保护语义：

- active Route 的 Checkpoint 保持 hot；
- active Intent 直接产生的 Checkpoint 保持 hot；
- settled Route 的旧 Checkpoint 可以进入 digest，但 digest 必须保留 `checkpoint_id`、`route_id` 和 Evidence refs；
- 被 active Route、Finding 或其他 Checkpoint 引用的 Claim 不得被物理删除；
- digest 只能替代上下文正文，不能替代引用和原始 Evidence；
- `covers` 只表示压缩视图，不参与真实因果关系。

## 6. Watchdog 实施方案

### 6.1 保留现有三层

继续使用：

- `RunMonitor`；
- Fast Path；
- Slow Path；
- Settlement；
- `watchdog_jobs`；
- `watchdog_requests`；
- `worker_runs`。

### 6.2 Fast Path

Fast Path 负责：

- Run 是否存在；
- Task 是否暂停、删除或结束；
- Task deadline 是否到达；
- Worker Run 是否超过预算；
- Route 是否超过累计预算；
- 工具是否超过单次时限；
- 是否发生重复动作；
- Provider error；
- 暂停、停止和 Settlement 请求。

Fast Path 不等待模型。

### 6.3 Slow Path

Slow Path 输入增加：

- Goal；
- Route objective；
- phase；
- Checkpoint；
- 高价值 ProgressEvent；
- Run 和 Route 预算；
- 重复动作摘要；
- Evidence refs；
- Finding Candidate 状态。

输出继续使用：

```text
continue
terminate
ask_user
provider_error
```

需要 handoff 时使用现有 Settlement reason 表达，不增加第二套外部状态机。

### 6.4 ProgressEvent

在现有 activity metadata 或 fact payload 中记录：

```text
observation
new_asset
new_claim
hypothesis_supported
hypothesis_rejected
validated_weakness
credential_obtained
privilege_change
lateral_progress
objective_milestone
finding_written
cleanup_completed
duplicate_action
provider_failure
```

规则：

- `new_asset` 更新 activity，但默认不恢复完整预算；
- `validated_weakness`、`privilege_change`、`objective_milestone` 可以重置当前观察计时；
- `duplicate_action` 不重置周期；
- `finding_written` 更新 Finding 和 Route 状态；
- 普通 Claim 只有关联当前 objective 时才算高价值进展。

### 6.5 预算分层

```text
Task deadline
Route deadline
Worker Run deadline
Tool deadline
Token budget
Tool-call budget
```

`watchdog_max_auto_cycles` 只控制自动继续周期数量。新 Run 继续同一 Route 时继承剩余预算。

## 7. Planner 实施方案

Planner 继续是唯一 Intent 生成者，不新增全局 Router LLM。

每轮 Planner 读取：

```text
当前 Route
当前 phase
当前 Checkpoint
剩余预算
最近高价值进展
未解决 Hypothesis
相关 Evidence refs
当前 Findings
```

继续复用：

- `graph_overview`；
- `node_detail`；
- `list_facts`；
- `list_findings`；
- `get_worker_output`；
- `get_worker_trace`；
- `search_all_worker_traces`；
- persistent todo。

Intent payload 至少包含：

```json
{
  "route_id": 101,
  "route_kind": "path_stage",
  "objective": "验证对象级授权边界",
  "phase": "validation",
  "asset_ids": [12],
  "parent_intent_id": 55,
  "checkpoint_fact_id": 1010,
  "expected_evidence": ["不同用户对象的响应差异"],
  "success_condition": "确认跨用户读取或排除该假设",
  "budget": {
    "max_tool_calls": 60,
    "max_input_tokens": 120000
  }
}
```

`open_intent_cap` 继续限制 frontier 数量，不承担 Route 和 Worker Run 预算。

## 8. Finding 实施方案

### 8.1 Candidate 映射

初期不扩展 `findings` 表状态枚举。候选漏洞使用 fact 节点：

```json
{
  "fact_type": "finding_candidate",
  "summary": "未认证请求可能读取其他用户对象",
  "claim_ids": [1010],
  "hypothesis_ids": [1011],
  "evidence_refs": ["traffic:123"],
  "validation_state": "pending",
  "confidence": "medium"
}
```

证据满足确认条件后，调用现有 `report_finding` 创建 `findings` 行和 finding 节点。

### 8.2 Run 结束对账

```text
读取本 Run 新增 Claim/Hypothesis
  -> 读取相关 traffic/artifact
  -> 检查 Candidate 和 Finding
  -> 创建或更新 finding_candidate fact
  -> reporter 生成正式报告
```

确认 Finding 必须有明确目标、可复现证据、真实影响、Evidence 引用、适用范围和时间。

## 9. 图压缩实施方案

### 9.1 Asset Graph

- 使用现有程序去重；
- 使用 `last_seen` 和来源记录观察有效性；
- 不保存攻击推理；
- 资产详情通过查询 Route Graph 反查路线；
- 资产图只保存资产身份、拓扑和当前资产视图。

### 9.2 Route Graph

继续使用：

- `exploration_nodes`；
- `exploration_edges`；
- `exploration_anchors`；
- Intent payload；
- Checkpoint fact；
- `worker_runs`。

继续使用 `coldgraph.go`：

- live Intent 及其祖先保持 hot；
- settled Intent 和普通 Claim 经过冷却周期后可以压缩；
- Finding、Goal、Hint、Begin 和 active Checkpoint 不直接折叠；
- digest 使用 `covers`；
- digest 不参与因果关系；
- content version 和 signature 防止重复摘要。

### 9.3 Information Graph

逻辑映射：

| 语义 | 当前来源 |
| --- | --- |
| Observation | activity、traffic、artifact |
| Claim | `fact_type=claim` fact |
| Hypothesis | `fact_type=hypothesis` fact |
| Decision | Intent payload、Checkpoint、activity metadata |
| Finding Candidate | `fact_type=finding_candidate` fact |
| Confirmed Finding | `findings` 和 finding 节点 |
| provenance | source task、source run、activity id、evidence refs |

### 9.4 Evidence Layer

Evidence Layer 不做有损图压缩。它引用或保存：

- 原始请求和响应；
- 命令输出；
- 文件快照；
- traffic body；
- artifact；
- screenshot；
- 审批和运行记录。

需要区分：

- Evidence Layer：系统语义层；
- `evidence.Store`：当前主要保证 traffic evidence 内容寻址和一致性的模块；
- `activity.detail`、`cmd-output`、transcript、任务目录：当前其他证据来源。

## 10. 恢复和持久状态

继续复用：

- `ResetRunningIntents`；
- Intent transcript resume；
- `worker_runs`；
- Watchdog cleanup；
- Settlement。

恢复时分别处理：

```text
Intent 状态
Worker Run 状态
Watchdog 控制状态
Route Checkpoint
Evidence 状态
```

旧 `run_id` 不得影响新 Run。新 Run 读取 Route ID、Checkpoint 和剩余预算。

服务重启后：

- running Intent 重新开放或恢复；
- 旧 Watchdog job 标为 stale；
- 旧判断卡不作用于新 Run；
- Claim、Finding、Evidence 保留；
- Planner 从最近 Checkpoint 继续；
- 累计预算不因重启恢复。

## 11. 实施阶段

### 阶段 1：观测和语义验证

不改变运行行为，检查：

- 每个 Run 的工具调用、token 和时长；
- phase 变化；
- Claim/Hypothesis/Finding Candidate 写入；
- Watchdog decision 输入和结果；
- Slow Path 过期率；
- Settlement 结果；
- Finding 缺失位置；
- Checkpoint 是否被 digest 错误处理。

重点回放任务 #3276 的 `14438`、`14461`、`14424`。

### 阶段 2：Checkpoint 和 Route 累计预算

复用 Intent payload、fact、activity 和 `worker_runs`：

- 保存 route_id、phase、objective、next_actions、Evidence refs；
- 计算 Worker Run 的工具、token 和时间使用；
- 新 Run 继承同一 Route 的剩余预算；
- Settlement 写入 Checkpoint；
- 先验证现有聚合是否稳定，不能稳定时再增加字段。

### 阶段 3：Watchdog 输入和进展判断

- Fast Path 读取固定预算和 Route 状态；
- Slow Path 读取 Checkpoint、Evidence 和 ProgressEvent；
- 普通 Claim/asset 不单独恢复完整周期；
- Watchdog 通过 Settlement reason 触发 handoff；
- 保留现有周期、判断卡、清理和 Settlement。

### 阶段 4：Finding Candidate 对账

- Run 结束时读取本 Run 新增 Claim/Hypothesis/Evidence；
- 创建或更新 `finding_candidate` fact；
- 证据满足条件后调用现有 `report_finding`；
- 使用现有 reporter 和 retester；
- 统计 Candidate recall、Confirmed recall 和报告完整度。

### 阶段 5：三图逻辑查询

- Asset Graph 使用现有 assets 和 anchors；
- Route Graph 使用 exploration nodes/edges、Intent payload、Checkpoint；
- Information Graph 使用 fact payload、activity、来源 metadata 和 findings；
- Evidence Layer 使用 evidence/traffic/artifact 引用；
- 前端先提供不同查询视图，不复制数据；
- 查询和事务验证证明现有结构不足时，才增加字段或表。

## 12. 施工分工

### 工作包 A：Information 类型和写入校验

文件范围：

- `agent/tools.go`
- `db/exploration.go`
- 相关 `agent/*_test.go`
- 相关 `db/*_test.go`

职责：

- 增加 `fact_type` 解析和校验；
- 校验 Evidence refs、activity ids、Claim/Hypothesis 引用；
- 保留旧 fact 的 `legacy_unknown` 兼容；
- 不改变现有 `fact` 节点物理类型；
- 不修改 Finding 确认规则以外的工具行为。

### 工作包 B：Route ID 和 Checkpoint

文件范围：

- `agent/tools.go`
- `db/exploration.go`
- `server/engine.go`
- `agent/terminalreason.go`
- 相关测试

职责：

- 生成并继承 `route_id`；
- 校验 continuation Intent 的来源；
- Settlement 写入 checkpoint fact；
- 记录 phase、objective、next actions、Evidence refs；
- 保留现有 Intent 状态转换和 CAS 逻辑。

### 工作包 C：Run 预算和 Watchdog 输入

文件范围：

- `server/watchdog_monitor.go`
- `server/watchdog_fast.go`
- `server/watchdog_service.go`
- `server/watchdog_decisions.go`
- `server/watchdog_config.go`
- `server/task_llm.go`
- `server/engine.go`

职责：

- 计算现有 Run 的工具、token、时间和 phase；
- 将 Path 累计预算与 cycle 预算分开；
- Slow Path 快照加入 Checkpoint、Evidence 和 ProgressEvent；
- 保留现有 `decideCycle`、Settlement、用户判断卡和 cleanup；
- 不重新实现 Watchdog 状态机。

### 工作包 D：Cold Digest 保护

文件范围：

- `agent/coldgraph.go`
- `agent/compaction.go`
- `db/exploration.go`
- `agent/*_test.go`

职责：

- 识别 checkpoint fact；
- 保持 active checkpoint hot；
- 保留被 active Route、Finding、其他 checkpoint 引用的 Claim；
- digest 保留 checkpoint、route、Evidence 引用；
- 保证 `covers` 不参与因果遍历。

### 工作包 E：Finding Candidate 对账

文件范围：

- `agent/tools.go`
- `server/engine.go`
- `evidence/store.go`
- 现有 reporter 触发路径
- 相关测试

职责：

- Run/Settlement 结束时检查 Claim、Hypothesis 和 Evidence；
- 创建或更新 `finding_candidate` fact；
- 只在证据满足条件后调用现有 `report_finding`；
- 保留 traffic binding 和 evidence version；
- 不新增平行 Finding 表。

### 工作包 F：查询视图和前端

文件范围：

- `server` 查询 DTO；
- `web/src/lib/types.ts`；
- 任务详情页；
- 资产详情页；
- 探索链路视图；
- Finding 详情页。

职责：

- Asset Graph 视图显示相关 Route；
- Route 视图显示资产、阶段、Checkpoint、Decision 和 Evidence refs；
- Information 视图区分 Observation、Claim、Hypothesis、Decision、Finding；
- Evidence 视图提供原始引用和版本；
- 不复制数据库正文，不改变现有活动顺序。

### 集成负责人

集成负责人负责：

- 维护跨工作包接口；
- 审查 `fact_type`、`route_id`、Checkpoint 和 Evidence refs；
- 统一测试 fixture；
- 按阶段运行真实 PostgreSQL 测试；
- 检查历史任务可读性；
- 最后运行完整构建和测试。

工作包之间共享 `db/exploration.go`、`agent/tools.go` 和 `server/engine.go` 时，必须串行集成，不允许并行覆盖同一函数。

## 13. 验证方法

### 13.1 状态和图语义

必须验证：

- Asset Graph 不混入 Model Decision；
- Route Graph 可以追踪 route_id、阶段和 Intent；
- continuation Intent 继承相同 route_id；
- Information Graph 区分 Observation、Claim、Hypothesis、Decision；
- `record_fact` 拒绝缺少来源的类型；
- Finding Candidate 不会进入 Confirmed Finding；
- Confirmed Finding 必须引用可回查 Evidence；
- active Checkpoint 不会被 cold digest 物理删除；
- 删除 Route 不会删除其他 Route 使用的 Claim 或 Evidence；
- Evidence 正文可以通过引用恢复。

### 13.2 Watchdog 回放

使用现有 trace 和确定性测试数据验证：

1. 持续写低价值 facts/assets，没有阶段进展；
2. 长工具持续产生阶段结果；
3. 相同工具、参数和结果重复执行；
4. Provider error 和重试；
5. Slow Path 晚于周期返回；
6. Watchdog 请求 Settlement；
7. Settlement 超时；
8. 同一 Route 开启新的 Worker Run；
9. 服务重启后恢复控制状态；
10. Finding 已有证据但 Worker 没有主动调用 `report_finding`。

### 13.3 任务 #3276 回放目标

重点回放：

- `14438`：何时产生第一个高价值 ProgressEvent；
- `14461`：切换题目后是否应结束当前 Intent；
- `14424`：同一 Route 多次 Run 如何继承预算；
- Slow Path 迟到前后是否改变周期决策；
- Settlement 是否保存全部已确认 Evidence；
- Finding 缺失发生在 Worker、Settlement 还是 reconciliation。

### 13.4 指标

| 指标 | 目标 |
| --- | --- |
| 低价值持续运行的 handoff/终止率 | 提升 |
| 有价值长工具的误终止率 | 不增加 |
| Slow Path 过期率 | 降低并可解释 |
| Run 结束后 Evidence 保留率 | 100% |
| Checkpoint 恢复后的重复动作比例 | 降低 |
| Finding Candidate recall | 提升 |
| Confirmed Finding 的 Evidence 完整率 | 提升 |
| 单个已验证 Finding 的 token 成本 | 降低 |
| 服务重启后的运行状态恢复率 | 100% |
| 旧控制记录影响新 Run 的次数 | 0 |
| Claim 被错误当作 Observation 的次数 | 0 |
| 未引用 Evidence 的 Confirmed Finding 数量 | 0 |

### 13.5 测试命令

后端专项测试：

```bash
go test -p 1 ./server ./db ./agent ./evidence -count=1
```

完整后端测试：

```bash
go test -p 1 ./... -count=1
```

构建和静态检查：

```bash
go build ./...
go vet ./...
```

前端：

```bash
cd web
npx tsc --noEmit -p tsconfig.json
NODE_OPTIONS=--max-old-space-size=8192 npx next build --webpack
```

执行顺序：

1. Information 写入校验；
2. Route ID 和 Checkpoint；
3. cold digest 保护；
4. Worker Run 和 Watchdog 预算；
5. Finding Candidate 对账；
6. 查询视图；
7. 全量后端测试；
8. 前端类型检查和构建。

## 14. 不纳入本方案

当前不建立：

- 全局 Router LLM；
- 独立 Operation 数据库层；
- 平行 Memory Store；
- 默认主动监听所有外部环境事件；
- 默认对真实目标执行投机动作；
- 新的消息总线；
- 跨任务共享完整 Worker 上下文；
- 将模型完整思维过程作为事实长期保存；
- 通过增加 Prompt 长度解决状态问题；
- 把所有命令输出和 artifact 强行迁移到当前 `evidence.Store`，除非先完成独立的数据迁移设计。

## 15. 方案依据

- ARTEX 架构说明：[README.md](../README.md)
- ARTEX Watchdog 设计：[ARTEX-Watchdog优化方案-11-19.md](./ARTEX-Watchdog优化方案-11-19.md)
- ARTEX Watchdog 施工记录：[ARTEX-Watchdog优化施工方案-11-19.md](./ARTEX-Watchdog优化施工方案-11-19.md)
- ARTEX 当前实现：`server/engine.go`、`server/task_llm.go`、`server/watchdog_*.go`、`agent/planner.go`、`agent/worker.go`、`db/exploration.go`、`evidence/store.go`
- Super-agent 设计参考：[Super-agent 设计探索 - 迈向更自主的 Agent 系统](<C:/Users/Administrator/Desktop/Agent/test/Super-agent 设计探索 - 迈向更自主的 Agent 系统.md>)
- NIST SP 800-115：[NIST SP 800-115](https://nvlpubs.nist.gov/nistpubs/legacy/SP/nistspecialpublication800-115.pdf)
- OWASP AI Agent Security：[AI Agent Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/AI_Agent_Security_Cheat_Sheet.html)

## 16. 最终设计判断

ARTEX 适合沿用现有的 Task、Exploration、Engine、Planner、Worker、Watchdog、Settlement 和 Evidence 实现，建立以下逻辑模型：

```text
Asset Graph
  全局资产身份、拓扑、范围和当前资产视图

Route Graph
  当前任务的稳定 route_id、阶段、Intent、Checkpoint 和 Decision

Information Graph
  Observation、Claim、Hypothesis、Finding 及其来源关系

Evidence Layer
  原始流量、文件、命令输出、artifact 和 activity 引用
```

三图不复制数据：

- Asset Graph 通过 anchors 被 Route Graph 引用；
- Route Graph 使用 Information Graph 的 Claim、Hypothesis 和 Decision；
- Information Graph 使用 Evidence Layer 的原始证据；
- Finding 通过 Evidence refs 形成可复核报告；
- Checkpoint 保护路线状态、预算和证据引用；
- cold digest 只压缩允许压缩的逻辑视图，不删除 active Checkpoint 和 Evidence。

施工重点是把现有对象之间的职责连接清楚：

```text
Planner 选择路线阶段
Worker 执行受控阶段
RunMonitor 记录运行状态
Watchdog 判断存活、进展和预算
Settlement 保存 Checkpoint
Exploration Graph 保存路线血缘
Information Graph 保存认识状态
Evidence Layer 保存原始材料引用
Reporter 生成报告
Retester 验证修复
```

最重要的实施结果是：同一条攻击路径可以跨多个受控 Worker Run 继续，同时保证：

- 资产身份和资产观察分离；
- Route ID 在 continuation Intent 之间保持稳定；
- Observation、Claim、Hypothesis、Decision 和 Finding 语义分开；
- 每个 Claim 和 Finding 的来源可以回查；
- Checkpoint 受到图压缩保护；
- 全局信息按来源、时间和任务范围过滤；
- Watchdog 具有明确的控制输入；
- 压缩和 handoff 不改变事实来源。
