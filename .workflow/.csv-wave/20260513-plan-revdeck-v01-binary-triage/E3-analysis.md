# E3 UX And Product Exploration

## Scope Guard

本探索只覆盖 RevDeck v0.1 Binary Triage MVP。依据 `RevDeck.txt` 的 MVP 裁剪，v0.1 闭环是“导入二进制 -> 自动索引 -> 函数雷达 -> 字符串/import/xref -> 笔记标签 -> finding -> 报告”。不应把 Trace Lab、Diff Lab、Firmware Lab、Crash Lab、Protocol Lab、Memory Lab 做成完整功能；v0.1 只保留能支撑 xrefs、本地对象导航和报告证据链的最小 hooks。

## Analyst Workflow

v0.1 的 analyst 体验应按一条可验收主线组织：

1. `revdeck open target.elf` 后进入项目，不落到空白 shell。
2. Overview 显示索引摘要：artifact、arch、sections、functions、strings、imports、findings、indexed status。
3. analyst 进入 Function Radar，按 score/reason 优先查看函数。
4. 从函数跳到引用字符串、危险 import、xref 列表，再返回原函数。
5. analyst 给对象添加 tag/status/note/rename/TODO/hypothesis。
6. analyst 将对象和注释提升为 finding evidence。
7. 导出 Markdown/JSON，报告保留 finding、severity、status、summary、tags、linked evidence、annotation context。
8. 关闭并重开项目后，导航对象、注释、renames、findings 和 evidence links 都可恢复。

产品重点不是“看更多反汇编”，而是持续回答 analyst 的两个问题：“我现在应该看哪里？”以及“我已经证明了什么？”。

## TUI Layout Findings

三栏布局是 v0.1 的核心产品 surface：

- Left Workspace：Overview、Binary Map、Function Radar、Strings、Imports、Functions、Notes、Findings。Graph/Trace/Diff/Firmware/Crash/Protocol/Memory 不作为 v0.1 主入口出现，避免暗示未交付能力。
- Center Main View：当前 lens 的 dense table/detail。Function Radar 应是默认高价值视图之一，包含 `score`、`function`、`size`、`calls/imports`、`strings`、`reasons`、`status/tags`。
- Right Inspector：永远显示 selected object 的类型、稳定 ID、名称/地址、tags、status、notes count、linked findings、backlinks、next actions。
- Bottom Command Bar：接受少量确定命令，建议首批包括 `:find`、`:xrefs`、`:tag`、`:note`、`:rename`、`:status`、`:finding new`、`:export markdown`、`:export json`、`:back`、`:forward`。

UX 风险：如果 Overview、Function Radar、Binary Map、Findings 都各自维护 selection，会造成对象状态分裂。应有单一 `selected_object_id` 和 navigation history，由 workspace shell 统一管理。

## Navigation Model Findings

Universal Object Navigation 的 v0.1 可执行边界应限制为已索引对象和 analyst-created objects：

- Indexed：artifact/file、section、function、string、import、xref。
- Analyst-created：note、tag、status、rename、TODO/hypothesis、finding。
- Typed edges：`CONTAINS`、`REFERENCES`、`CALLS_IMPORT`、`XREF_FROM`、`ANNOTATES`、`EVIDENCE_FOR`、`RENAMES`、`TAGGED_AS`。

最小验收路径：

- String -> xref -> Function -> Import。
- Import `system` -> callers/functions -> notes/tags。
- Finding -> evidence -> original Function/String/Import/Xref。
- Back/forward 恢复 lens、selection、cursor row 和 inspector。
- Broken evidence link 在 inspector 和 pre-export check 中清晰显示。

实现建议：不要让 TUI 直接拼路径或地址跳转，应通过 `ObjectRef { kind, id }` 和 `Relation { from, to, kind }` 查询；命令栏、table Enter、inspector backlinks 都调用同一个 `navigate_to(ObjectRef)`。

## Function Radar Product Behavior

Function Radar 是 v0.1 的“先看哪里”机制，必须可解释、可调试、可测试。

建议 score 分解：

- 引用敏感字符串：password、token、key、auth、admin、shell、cmd、debug、http。
- 调用危险/高信号 imports：system、popen、execve、strcpy、sprintf、memcpy、recv、read、open。
- 靠近入口点或被高频调用：基于 call/xref count 的启发式，不承诺完整 call graph。
- 函数规模和复杂度 proxy：instruction count、basic block count 可选；没有 CFG 时可先用 disasm span/size。
- 用户反馈：tags/status 可影响排序显示，但不应覆盖原始 evidence reasons。

UX 要求：每个 score 必须展示 `reasons`，并允许 analyst 从 reason 跳转到对应 string/import/xref。无 reason 的高分不可接受，因为它无法成为 evidence。

## Analysis Memory Findings

Analysis Memory 应被视为项目数据模型的一等公民，而不是 UI local state：

- Function rename 需要保存原始名称、用户名称、时间、来源 object。
- Tags/status 可挂到任意 object，状态建议最小集：`unreviewed`、`interesting`、`suspicious`、`reviewed`、`false_positive`。
- Notes/TODO/hypothesis 支持 linked object 和 optional evidence refs。
- Inspector 要显示 notes/tags/status，并支持从注释直接创建 finding evidence。
- Filter 应覆盖 annotated objects、tag、status、has_notes、has_findings。

关键验收：重开项目后，renamed function 在 Function Radar、Functions、Inspector、Finding export 中一致显示，同时保留稳定 object ID，避免 rename 破坏 evidence links。

## Findings Export Findings

Findings 是 v0.1 的交付层，最小字段：

- `id`、`title`、`severity`、`status`、`summary`、`tags`。
- `evidence[]`：`ObjectRef`、relation kind、display label、annotation context、broken flag。
- `created_at`、`updated_at`。

Markdown 导出面向人读，应按 severity/status 排序，并为每条 evidence 给出对象类型、名称/地址、相关 note/tag。JSON 导出面向 round-trip 和后续工具，必须保留稳定 IDs，不只导出 display text。

Pre-export check 是必要 UX：missing evidence、broken links、empty summary、unknown severity 应在 TUI 中可见；允许导出 draft，但必须标记。

## Feature-Level Planning Implications

建议下一步 feature-level plan 按依赖拆分：

- F-002 Workspace Shell：三栏 layout、selection、command bar、lens switching、terminal-size fallback。
- F-004 Object Navigation：ObjectRef、Relation、history、inspector backlinks、broken-link state。
- F-003 Function Radar：score engine、reason model、radar table、reason-to-object navigation。
- F-005 Analysis Memory：annotations schema、CRUD commands、persistence、filters、rename consistency。
- F-006 Findings Export：finding CRUD、evidence linking、pre-export validation、Markdown/JSON exporters。

跨 feature 验收场景应围绕一个小 ELF fixture：导入后出现高分函数，reason 指向 string/import；analyst 添加 tag/note/rename；创建 finding 并链接 evidence；导出 Markdown/JSON；重开项目后所有状态保持。

## Test Findings

- TUI：使用 deterministic fixture 和 snapshot/state tests 验证三栏布局在常见终端尺寸下仍有 workspace、main、inspector、command/status 区。
- Navigation：单元测试 `navigate_to`、history back/forward、broken object handling；集成测试 String -> Xref -> Function -> Import -> Back。
- Radar：对固定 fixture 断言 score ordering 和 reasons，不断言脆弱的绝对分值；每个 reason 必须有可跳转 ObjectRef。
- Memory：重开项目测试 notes/tags/status/rename/TODO/hypothesis 持久化；rename 后 evidence link 不断。
- Export：Markdown golden file；JSON round-trip；pre-export validation 覆盖 missing/broken evidence。

## Source Anchors

- `RevDeck.txt:1203` 附近明确 v0.1 MVP 裁剪。
- `RevDeck.txt:1209` 给出核心闭环。
- `RevDeck.txt:1415`、`RevDeck.txt:1423` 标出 Universal Jump 与 Analysis Memory 为差异化卖点。
- `.workflow/scratch/20260513-revdeck-v01-binary-triage/context.md:8` 定义 Product Goal。
- `.workflow/scratch/20260513-revdeck-v01-binary-triage/context.md:22` 定义 v0.1 scope。
- `F-002-terminal-workspace-shell.md` 定义三栏、command bar、selection/inspector 验收。
- `F-004-universal-object-navigation.md` 定义 typed edges、history、backlinks、broken links。
- `F-005-analysis-memory.md` 定义 notes/tags/renames/status/TODO/evidence links。
- `F-006-findings-and-report-export.md` 定义 finding evidence 和 Markdown/JSON export。
