# E1 Architecture Exploration

## 输入边界

本探索只基于 `RevDeck.txt`、本次 v0.1 planning context，以及 brainstorm 产物。`RevDeck.txt` 的产品全景很大，但 v0.1 被明确砍成 Binary Triage 闭环：导入二进制、自动索引、函数雷达、字符串/import/xref、笔记标签、finding、报告。Trace Lab、Diff Lab、Firmware Lab、Crash Lab、Protocol Lab、Memory Lab、插件市场、完整 CFG/反编译、动态调试和漏洞利用不进入 v0.1 主体。

关键来源锚点：
- `RevDeck.txt:742`：统一对象图是核心产品抽象。
- `RevDeck.txt:830`：TUI 命令栏与对象跳转是主交互入口。
- `RevDeck.txt:931`：四层后端架构：TUI、Workspace、Core Engine、Analysis Plugins、External Tool Adapters。
- `RevDeck.txt:990`：项目数据库第一版使用 SQLite。
- `RevDeck.txt:1203`：MVP 应砍成 Binary Triage 闭环。
- `RevDeck.txt:1251`：v0.1 重点是单个二进制快速摸底。
- Brainstorm guidance：F-001 到 F-006 是 v0.1 主线，F-007/F-008 只保留最小 hooks/contract。

## 推荐架构切片

建议从一个 Rust workspace 或单 crate 模块化开始，避免一开始拆成过多 crate。模块边界可以按四层组织：

1. `cli` / `main`
   - 负责 `revdeck new/open/import/export` 等入口参数。
   - 启动 TUI 或执行非交互命令。

2. `tui`
   - Ratatui 三栏布局：左侧 workspace/lens 导航，中间 active lens，右侧 inspector，底部 command bar/status。
   - 不直接访问解析器，只通过 workspace/core query API 读取 project state。
   - 初始 lenses：Overview、Binary Map、Function Radar、Strings、Imports、Notes、Findings。Graph Lab 只作为 xref/local neighborhood 入口，不做全局图渲染。

3. `workspace`
   - 管理当前 project、active lens、selection、navigation history、command routing、inspector model。
   - 提供 `ObjectRef` 驱动的 universal jump：任何 UI 选择都落到 `ObjectRef`，再查询相关 `Edge` 和 annotation。

4. `core`
   - 产品资产层：object graph、stable IDs、query service、jobs/analysis runs、annotations、findings、report export、Function Radar scoring。
   - Function Radar 不应依赖 ELF parser 内部结构，只读取 normalized objects/edges 和 annotation/tag。

5. `storage`
   - SQLite migrations、transaction boundary、repository/query API。
   - 所有 importer/analyzer 输出必须通过 transaction 写入对象、边、run record 和 diagnostics，失败不能污染已提交状态。

6. `adapters`
   - `Importer`：接收 artifact，产出 artifact/file/binary/section/symbol/string/import/function/xref 等 normalized records。
   - `Analyzer`：接收已有 objects/edges，产出派生 objects/edges/scores/diagnostics，例如 string scan、function radar、xref enrichment。
   - v0.1 可实现 native ELF importer 和一个 fixture/mock external adapter contract；不要做插件市场。

7. `export`
   - Markdown 和 JSON report exporter。
   - 输入是 findings + evidence graph + annotation context，不应遍历 TUI 状态。

## 数据模型

v0.1 应采用 SQLite 作为 source of truth，并显式保存对象图。建议核心表：

- `projects` 或 project metadata：schema version、created_at、updated_at、settings。
- `artifacts`：artifact id、display name、source path、copied path、sha256/blake3、kind、size、import status。
- `analysis_runs`：run id、artifact id、adapter/analyzer id、version、input hash、status、started/finished、error summary。
- `objects`：object id、artifact id、kind、stable key、address/range、name、display、metadata JSON。
- 专用索引表：`sections`、`symbols`、`functions`、`strings`、`imports`、`xrefs`。这些表可以复用 `object_id`，承载查询性能所需字段。
- `edges`：edge id、src object id、dst object id、edge kind、confidence、source run id、metadata JSON。
- `scores`：object id、score kind、value、reason codes、source run id。
- `annotations`：note/tag/rename/status/todo/hypothesis，全部挂到 object id。
- `findings`：severity、status、summary、body、tags、timestamps。
- `finding_evidence`：finding id、object id、edge/evidence role、order、note。
- `navigation_events` 可不落库；back/forward history 初期保存在 workspace state，后续可选持久化。

对象 ID 不能只依赖随机 UUID，也不能只依赖地址。推荐用稳定 key 生成：

- artifact：内容 hash + normalized relative path。
- section：artifact id + section name + virtual address + size。
- function：artifact id + address range + symbol/name when available。
- string：artifact id + address/offset + value hash。
- import：artifact id + library + symbol。
- annotation/finding：可用 ULID/UUID，因为它们是用户创建对象，但 evidence link 必须引用稳定 object id。

## 对象图边界

v0.1 只需要覆盖 Binary Triage 关系：

- `CONTAINS`：artifact/file/binary -> section/function/string/import。
- `REFERENCES`：function -> string/address/import。
- `CALLS`：function -> function/import，初期允许低置信度或仅保存 importer 可确定的调用。
- `HAS_XREF` 或 `REFERENCED_BY`：string/import/address -> function，便于 UI 反向跳转。
- `ANNOTATES`：annotation -> object。
- `EVIDENCE_FOR`：object/annotation/xref -> finding。
- `DERIVED_FROM`：score/xref/analysis output -> analysis run。

Graph Lab Seed 在 v0.1 应只是这些边的局部查询：callers/callees、string/import xrefs、finding evidence chain。不要把完整 CFG、source-to-sink 和全局图渲染作为计划主线；如果做 simple path，只基于 `edges` 的 bounded traversal。

## Importer / Analyzer 边界

`Importer` 和 `Analyzer` 应该是同步或异步 job 的纯边界，而不是 UI 插件。

推荐接口概念：

```rust
trait Importer {
    fn id(&self) -> &'static str;
    fn version(&self) -> &'static str;
    fn supports(&self, artifact: &ArtifactInput) -> bool;
    fn import(&self, ctx: &ImportContext, out: &mut dyn ObjectSink) -> Result<ImportSummary>;
}

trait Analyzer {
    fn id(&self) -> &'static str;
    fn version(&self) -> &'static str;
    fn inputs(&self) -> AnalyzerInputs;
    fn analyze(&self, ctx: &AnalysisContext, out: &mut dyn ObjectSink) -> Result<AnalysisSummary>;
}
```

核心约束：
- `ObjectSink` 只接受 normalized records：objects、edges、scores、diagnostics。
- Storage 层负责 transaction、ID 冲突、upsert、run record 和 rollback。
- Native ELF importer 首先产出 sections、symbols、imports、entrypoint、strings、可确定函数。
- Basic disassembly/function discovery 可独立为 analyzer；先从 symbols/import thunk/entrypoint 和简单 heuristic 起步，避免承诺完整函数恢复。
- External adapter boundary 先用 fixture JSON contract 验证 schema，不要求 Ghidra/radare2/Frida 等真实集成。

## Integration Points

- Project ingest -> storage：创建 `.revdeck/project.sqlite`，复制或引用 artifact，记录 hash 和 import run。
- Indexing -> object graph：ELF parser、string scanner、import extractor、function/xref analyzer 都写入同一个 object/edge schema。
- Function Radar -> query service：读取 functions、calls/imports、strings、xrefs、tags/status，生成 deterministic score + reason codes。
- TUI -> workspace/core：所有 selection 都是 `ObjectRef`；inspector 查询 current object 的 metadata、edges、annotations、findings。
- Command bar -> command parser -> workspace action：`:find string password`、`:xrefs system`、`:tag current suspicious`、`:rename current ...`、`:finding new ...`。
- Analysis Memory -> storage：notes/tags/renames/status/todo/hypothesis 独立于 importer run，re-index 不得删除用户数据。
- Findings/export -> evidence graph：exporter 从 finding evidence link 回溯对象、notes、tags、xref context，生成 Markdown/JSON。

## 推荐 Rust crates

- TUI：`ratatui` + `crossterm`。符合 source 中 Rust + Ratatui 建议，支持 test backend 做状态级 UI 测试。
- CLI：`clap`。用于 project/import/export 命令。
- SQLite：`rusqlite` + `refinery` 或 `barrel`/SQL migrations。v0.1 本地 DB 同步访问更简单，`sqlx` 的 async/compile-time SQL 对 TUI MVP 未必值得。
- Serialization：`serde`、`serde_json`、`toml`。用于 adapter fixture、metadata JSON、export JSON、settings。
- Binary parsing：`goblin` 或 `object`。v0.1 主攻 ELF，`goblin` 上手直接；若要统一 ELF/PE/Mach-O 元数据，`object` 也可评估。
- Disassembly：`capstone`。仅用于 basic disassembly 和有限 xref/call heuristic，不承诺完整 CFG。
- String scan：`memchr`、`aho-corasick`、`regex`。用于 ASCII/UTF-16 字符串抽取和敏感关键字 reason。
- Graph：`petgraph`。用于 bounded local graph/path 查询；SQLite `edges` 仍是 source of truth。
- Errors/logging：`thiserror`、`anyhow`、`tracing`、`tracing-subscriber`。
- IDs/hash/time：`blake3` 或 `sha2`、`ulid`/`uuid`、`time`。
- Tests：`tempfile`、`assert_cmd`、`predicates`、`insta`、Ratatui `TestBackend`。

## UX 发现

- 首屏应是工作台，不是 landing page。打开 project 后展示 Overview/Function Radar，高亮 artifact metadata、index status、top functions、suggested next actions。
- 三栏布局必须稳定：workspace navigation、main lens、inspector。切换 lens 不应丢失 selection/history。
- Inspector 是 object graph 的主要可见化入口：当前 function 的 score reasons、strings、imports、xrefs、tags、notes、findings 都在这里聚合。
- Command bar 要服务 analyst questions，而不是展示技术能力。v0.1 至少支持 find/xrefs/tag/rename/note/finding/export。
- Broken links、partial indexing、unsupported binary 必须在 UI 中可见，避免让用户误以为无结果。

## 测试发现

- Fixture-first：最小 ELF、stripped ELF、含敏感字符串和危险 import 的 ELF、corrupt artifact、mock external adapter JSON、带 notes/tags/findings 的 project。
- Import/index tests：断言 object counts、stable IDs、analysis run status、diagnostics、partial failure 行为。
- Storage/migration tests：schema 初始化、reopen project、annotation 在 re-index 后仍挂到同一 object。
- Function Radar tests：固定 fixtures 的排序、score value、reason codes，避免非确定性。
- Navigation tests：string -> xref -> function -> import -> note -> finding，back/forward restore selection。
- Command parser tests：正常命令、ambiguous target、invalid syntax、current object fallback。
- Export tests：Markdown 可读、JSON round-trip 关键字段、missing evidence warning。
- TUI tests：先做 app state 和 Ratatui TestBackend snapshot；不需要早期引入复杂端到端终端自动化。

## Feature-level Plan 建议

可执行任务拆分建议：

1. Project DB and schema：SQLite、migrations、stable object IDs、analysis run、repositories。
2. Native ELF ingest：artifact registration、sections/symbols/imports/strings、structured errors。
3. Object graph and query API：objects/edges、ObjectRef、related object queries、bounded traversal。
4. Workspace/TUI shell：三栏布局、lens switching、selection、inspector、command bar skeleton。
5. Function Radar：scoring signals、reason codes、sort/filter、inspector integration。
6. Analysis Memory：notes/tags/renames/status/todo/hypothesis、annotation filters、reopen persistence。
7. Universal Navigation：jump actions、xrefs、back/forward history、broken-link diagnostics。
8. Findings/export：finding CRUD、evidence links、Markdown/JSON export。
9. Adapter contract seed：mock external JSON adapter、adapter metadata/version/error contract。

依赖顺序应先稳定 Project DB、ObjectRef 和 object graph，再做 TUI 与 Radar；否则 notes/findings/export 容易变成页面私有状态，后续难以统一。

## 风险与约束

- Function boundary accuracy 是最大技术不确定性。v0.1 应明确区分 symbol-derived functions、heuristic-derived functions 和 external-adapter-derived functions，并在 UI 中展示 confidence/source。
- Address-only identity 会在 re-index、stripped binary、future diff 场景中出问题；v0.1 就需要 stable key 规范。
- Re-index 不能覆盖用户 renames/tags/status；importer/analyzer 写入域与 analyst-owned annotation 域必须分离。
- External tool ambitions容易拖垮 MVP；F-008 应只定义 contract 和 mock fixture，不实施 Ghidra/radare2 集成。
- Graph 只做本地 object navigation；完整 CFG、source-to-sink、global call graph 应推迟到 v0.2+。
