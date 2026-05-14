# RevDeck

RevDeck 是一个终端原生、native-first 的逆向分析工作台。它当前聚焦 v0.1 的闭环：导入一个二进制，建立项目数据库，索引 sections、symbols、imports、strings、functions 和关系边，然后在 TUI 中完成 triage、跳转、笔记、finding 和报告导出。

RevDeck 的核心 analyzer、项目模型、TUI 和 plugin runtime 都由 RevDeck 自己拥有。外部逆向工具可以作为能力参照或离线验证参考，但不是运行时依赖，也不是兼容层前提。

## 当前能做什么

- 直接分析 ELF 或 PE/EXE：`revdeck analyze <binary>` 会创建默认项目、导入目标，并打开 TUI。
- 项目化存储：RevDeck 使用 SQLite 保存 artifacts、analysis runs、objects、edges、findings 和 session memory。
- 自动 triage：Function Radar 会根据危险 import、敏感字符串、调用关系、函数边界置信度等信号给函数排序。
- 三栏 TUI：左侧 Workspace，中央 Main View，右侧 Inspector，底部 Command / Status。
- Graph Lab：可以从当前对象打开局部关系图，查看 xrefs、calls、evidence path，以及 native function -> basic block -> instruction 关系。
- Command Deck：可以用命令面板查看常用动作、当前对象和命令预览。
- Native Analyzer foundation：导入时会生成 instruction、basic block、CFG edge，以及基础的 native call / branch / RIP-relative string / PE IAT import xref。
- x86-64 typed operands：当前能识别寄存器、内存、relative target 和 immediate operand，覆盖常见 REX.W `mov`、`cmp`、`test`、`call`、`jmp`、RIP-relative load、PE IAT call / thunk。
- 条件来源追踪：basic block 内的 `cmp` / `test` 会链接到后续 conditional branch，Inspector 和 Graph Lab 能显示 branch 依赖的 flag producer。
- 函数发现：除了 symbol 和 entrypoint，native analyzer 会从 executable section 中的 direct `call rel32` 发现保守的 `call_target` 函数候选，并按相邻函数入口/section 末尾收紧函数范围。
- 跨对象跳转：函数、字符串、import、finding 和关系边可以通过当前选择或命令跳转。
- 笔记与分析记忆：可以给当前对象添加 tag、note、rename、status。
- finding 草稿：可以在 TUI 命令栏创建 finding，并把证据对象链接进去。
- 报告导出：支持 JSON 和 Markdown 报告导出。TUI 中 queued 的 export 会在退出 TUI 时写入项目目录。

当前还不做完整反编译、完整指令集覆盖、动态调试、固件解包、trace 导入、crash 聚类和完整插件生态。当前 xref 和函数恢复仍是保守子集，这些属于后续路线。

## 安装

### 从源码安装到全局命令

需要 Rust toolchain：

```powershell
cargo install --path crates/revdeck-cli --locked
```

安装后确认：

```powershell
revdeck --help
```

在 Windows 上，Cargo 默认会把 `revdeck.exe` 安装到：

```text
%USERPROFILE%\.cargo\bin\revdeck.exe
```

如果命令行找不到 `revdeck`，把 `%USERPROFILE%\.cargo\bin` 加到 `PATH`。

### 本仓库内临时运行

不全局安装时，可以在仓库根目录运行：

```powershell
cargo run -p revdeck-cli -- analyze .\fixtures\binaries\sensitive_imports_elf
```

## 快速开始：直接打开 EXE 分析

最直接的用法是：

```powershell
revdeck analyze C:\path\to\target.exe
```

这会做 3 件事：

1. 在当前目录下创建默认项目目录：`.revdeck\workspaces\<target>-<hash>`。
2. 导入并索引这个 EXE。
3. 自动进入 TUI。

如果只想导入和输出 JSON 摘要，不进入 TUI：

```powershell
revdeck analyze C:\path\to\target.exe --no-tui
```

指定项目目录：

```powershell
revdeck analyze C:\path\to\target.exe --project .\my-revdeck-project
```

再次打开已经创建的项目：

```powershell
revdeck tui .\my-revdeck-project
```

## CLI 命令

### `revdeck analyze <binary>`

一站式命令。创建或打开项目、导入二进制、索引、默认进入 TUI。

常用参数：

```powershell
revdeck analyze .\sample.exe
revdeck analyze .\sample.exe --no-tui
revdeck analyze .\sample.exe --project .\projects\sample
revdeck analyze .\sample.exe --profile quick
```

`--profile` 控制分析深度：

- `quick`：优先快速打开项目，保留 sections、imports、strings、function seeds 和基础 xrefs，跳过 native CFG / instruction 持久化，并在 JSON diagnostics 中记录 `pass_skipped_by_profile`。
- `balanced`：默认行为，执行当前 native CFG 和函数评分流程。
- `deep`：保留给后续更重分析；当前等同 `balanced`。

### `revdeck init <project_dir>`

初始化一个空项目数据库。

```powershell
revdeck init .\case-001
```

### `revdeck open <project_dir>`

检查并打开已有项目，输出数据库路径。

```powershell
revdeck open .\case-001
```

### `revdeck import <project_dir> <binary>`

把二进制导入已有项目。

```powershell
revdeck import .\case-001 .\sample.exe
revdeck import .\case-001 .\sample.exe --profile quick
```

### `revdeck jobs <project_dir>`

查看最近的分析 pass/job 状态。`quick` profile 会把 native CFG 相关 pass 标记为 `skipped`，用于区分失败和主动降级。

```powershell
revdeck jobs .\case-001
revdeck jobs .\case-001 --limit 20
```

### `revdeck tui <project_dir>`

打开项目 TUI。

```powershell
revdeck tui .\case-001
```

### `revdeck stats <project_dir>`

查看数据库统计。

```powershell
revdeck stats .\case-001
```

输出包括 schema version、artifact 数、analysis run 数、object 数、edge 数、instruction 数、basic block 数和 CFG edge 数。

### `revdeck report <project_dir>`

导出 findings 报告。

```powershell
revdeck report .\case-001 --format json --out report.json
revdeck report .\case-001 --format md --out report.md
```

如果没有 `--out`，报告会直接输出到终端。

### `revdeck index <project_dir> [artifact_id]`

当前是保留命令。主要用于后续重新索引流程。

## TUI 布局

RevDeck 的 TUI 是固定的工作台结构：

```text
Cockpit
Workspace | Main View | Inspector
Command / Status
```

- `Cockpit`：显示目标、analysis/import 状态、当前 view/focus、对象计数和 selected。
- `Workspace`：选择当前分析视图。
- `Main View`：显示当前视图的列表、表格或概览。
- `Inspector`：显示当前对象的上下文、评分原因、证据和关系。
- `Command / Status`：输入命令、查看状态和当前界面提示。

## TUI 操作

RevDeck 现在使用“面板焦点”模型，而不是用 `Tab` 直接切视图。

| 按键 | 作用 |
| --- | --- |
| `Tab` | 在 `Workspace -> Main View -> Inspector` 之间循环切换焦点 |
| `Shift+Tab` | 反向切换焦点 |
| `Right` | 移到右侧栏目 |
| `Left` | 移到左侧栏目 |
| `Up` / `Down` | 在当前焦点面板内移动 |
| `j` / `k` | 等同于 `Down` / `Up` |
| `Enter` | 打开当前行，或在 Inspector 中跳到当前证据/关系 |
| `?` / `h` | 打开或关闭当前上下文帮助浮层 |
| `p` / `Ctrl+P` | 打开或关闭 Command Deck |
| `:` | 进入命令模式 |
| `Esc` | 退出程序，命令模式中表示取消命令 |
| `q` | 退出程序 |
| `g` | 快速切到 Triage Board |
| `G` | 切到 Graph Lab / Local Relations |
| `o` | 切到 Overview |
| `b` | 切到 Binary Map |
| `r` | 切到 Function Radar |
| `f` | 切到 Functions |
| `s` | 切到 Strings |
| `i` | 切到 Imports |
| `n` | 切到 Notes |
| `F` | 切到 Findings |
| `[` | 后退导航历史 |
| `]` | 前进导航历史 |

焦点在不同面板时，`Up` / `Down` 的含义不同：

- 在 `Workspace`：切换左侧视图。
- 在 `Main View`：移动当前视图中的主选择。
- 在 `Inspector`：移动证据或关系项，`Enter` 可以跳转到对应对象。

帮助浮层打开时，`Up` / `Down` / `Tab` 不会改变当前选择；按 `?`、`h`、`Esc` 或 `q` 关闭浮层后继续操作。Windows 终端里的按键 release 事件会被忽略，所以一次按键只应移动一次。

## 每个界面可以做什么

### Overview

项目总览。用来看当前目标是什么、索引状态如何、有多少 sections、functions、strings、imports 和 findings。

适合做：

- 打开项目后快速确认导入是否成功。
- 查看 Top Function Radar。
- 发现索引退化或解析警告。
- 作为分析入口判断下一步去 Triage Board 还是 Function Radar。

### Triage Board

下一步行动列表。它把 warnings、高分函数、finding gap 组织成优先级队列。

适合做：

- 快速看到最值得先看的对象。
- 处理 `P0` / `P1` 高优先级线索。
- 跟着 `commands` 栏里的建议执行 `:xrefs current`、`:open current`、`:note reviewed`。
- 判断高分函数是否已经沉淀成 finding。

### Binary Map

二进制结构概览。当前显示 artifact、导入状态、sections、functions、strings、imports 计数。

适合做：

- 确认目标是否被识别和索引。
- 粗看二进制规模。
- 后续会扩展为 sections、symbols、imports、entropy 和格式细节入口。

### Function Radar

函数优先级雷达。它按风险和分析价值排序函数，并显示 score、address、size、calls、strings、boundary 和 reasons。

适合做：

- 找到最值得先看的函数。
- 优先处理调用危险 API 或引用敏感字符串的函数。
- 用 `Enter` 打开当前函数，让右侧 Inspector 显示评分原因和证据。
- 结合 `:xrefs current` 看当前函数关系。

### Graph Lab

局部关系图。它围绕当前对象显示 xrefs、calls、contains、evidence 等关系。

适合做：

- 从当前函数查看危险 import、敏感字符串或 evidence path。
- 用 `G` 快速围绕当前对象打开局部图。
- 用 `:xrefs current` 刷新关系上下文。
- 在关系行和 Inspector 之间跳转，追踪 source 到 sink。

### Functions

函数列表。显示当前索引到的函数对象。

适合做：

- 按函数对象浏览项目。
- 从普通函数列表进入 Inspector。
- 配合 `:tag current ...`、`:note current ...` 做人工整理。

### Strings

字符串列表。显示字符串对象、地址和标签。

适合做：

- 浏览可疑字符串，例如 password、token、cmd、URL、路径。
- 用 `:find string password` 搜索。
- 打开字符串后在 Inspector 中看引用关系。

### Imports

导入表视图。显示导入 API 或库符号。

适合做：

- 找 `system`、`popen`、`exec`、`CreateProcess`、`LoadLibrary` 等敏感 import。
- 打开 import 后看引用关系。
- 给危险 API 做标签或笔记。

### Notes

分析记忆视图。显示 session 中产生的 tag、note、rename、status，以及数据库里的 annotation 对象。

适合做：

- 回看自己已经标记过的对象。
- 检查哪些函数已经 reviewed、suspicious、confirmed。
- 将临时判断整理成 finding。

### Findings

结论视图。显示已记录 findings 和当前 session 中新建的 finding 草稿。

适合做：

- 管理最终要交付的结论。
- 创建高危/中危/低危 finding。
- 链接证据对象。
- 导出报告前检查 finding 状态。

### Inspector

右侧上下文面板。它不是独立视图，而是当前选中对象的上下文。

适合做：

- 查看当前对象 ref、address、size、radar score、boundary。
- 查看 Function Radar 的 score reasons。
- 在 evidence 行按 `Enter` 跳到字符串或 import。
- 查看 backlinks / relations 并按 `Enter` 跳转。
- 查看当前对象的 tags、notes、rename 和 status。

## 命令栏

按 `:` 进入命令模式。命令可以省略开头的冒号，但建议保留。

常用命令：

```text
:find string password
:find import system
:xrefs current
:open current
:tag current suspicious
:note current reviewed dangerous import path
:rename current handle_debug_command
:status current reviewed
:finding new high command execution path
:finding link current current evidence
:export json report.json
:export markdown report.md
:help
```

命令目标常用 `current`，表示当前选中的对象。

TUI 命令产生的 `tag`、`note`、`rename`、`status`、finding 草稿和 finding evidence 会在退出 TUI 时写入项目数据库。`:export ...` 在 TUI 中先进入队列，退出 TUI 时会基于持久化后的 findings 生成报告文件。

## 推荐分析流程

### 单个 EXE 快速摸底

```powershell
revdeck analyze C:\samples\target.exe --profile quick
```

进入 TUI 后：

1. 在 `Overview` 确认导入状态和对象计数。
2. 按 `g` 进入 `Triage Board`，看最高优先级 next action。
3. 按 `r` 进入 `Function Radar`，优先看高分函数。
4. 在函数上按 `Enter`，用 `Right` 进入 `Inspector`。
5. 在 Inspector 中用 `Up` / `Down` 选择 evidence，按 `Enter` 跳到字符串或 import。
6. 用 `:xrefs current` 看当前对象关系。
7. 用 `:tag`、`:note`、`:status` 留下分析记忆。
8. 用 `:finding new ...` 和 `:finding link ...` 形成结论。
9. 退出后用 `revdeck report` 导出报告。

### 已有项目继续分析

```powershell
revdeck tui .\case-001
```

继续从 `Notes`、`Findings` 或 `Triage Board` 接上之前的上下文。

## 项目目录

默认 `analyze` 会创建：

```text
.revdeck/
  workspaces/
    <binary-name>-<hash>/
      revdeck.sqlite
```

指定 `--project` 时，数据库会放在指定项目目录里。

## 当前路线

v0.1 目标是 Binary Triage：

- 项目数据库
- ELF / PE 导入
- sections / symbols / imports / strings / functions
- native instructions / basic blocks / CFG edges
- Function Radar
- xrefs / relation navigation
- notes / tags / findings
- TUI 三栏工作台
- JSON / Markdown 报告

后续方向：

- Graph Lab：局部 call graph、xref graph、路径视图。
- Native Analyzer：更完整的 instruction coverage、函数恢复、CFG、call graph、数据流和 xref 恢复。
- Diff Lab：版本差异、字符串/import/function diff。
- Trace Lab：JSONL trace 导入和时间线。
- Firmware Lab：固件目录和批量 ELF 分析。
- Crash Lab：ASAN / UBSAN / panic log 聚类。
- Protocol Lab：消息、字段和协议样本分析。
- Plugin API：导入器、分析器、视图、评分器、导出器。

## Plugin SDK Preview

RevDeck 现在有一个本地 plugin SDK preview 的基础骨架。它不是 marketplace，也不是完整 sandbox；当前目标是先锁定插件合约和测试入口。

当前支持：

- `revdeck plugin validate <revdeck-plugin.toml>`：校验插件 manifest。
- `revdeck plugin inspect <revdeck-plugin.toml>`：输出插件能力、权限和校验结果。
- `revdeck plugin test <plugin_dir>`：校验 manifest，并在存在 `object-batch.json` 时执行 ObjectBatch dry-run。
- `revdeck plugin commit <project_dir> <plugin_dir>`：校验并通过 host 把 ObjectBatch 提交到项目数据库。
- `revdeck plugin run <project_dir> <plugin_dir> --commit`：以 fixture replay 模式运行本地插件输出并提交。

最小插件目录：

```text
my-plugin/
  revdeck-plugin.toml
  object-batch.json
```

Manifest 示例：

```toml
[plugin]
id = "com.example.object-batch-import"
version = "0.1.0"
sdk_version = "0.1.0"
revdeck_compat = ">=0.1,<0.3"

[[capabilities]]
id = "object-batch-import"
kind = "importer"
inputs = ["object-batch-json"]
outputs = ["object_batch"]

[permissions]
artifact_read = ["object_batch_fixture"]
project_write = ["objects", "edges", "attributes", "diagnostics"]
network = false
process_spawn = false
```

安全边界：

- 默认不授予 network、process spawn、secrets、environment 或文件写权限。
- 插件不能通过 SDK 直接写 SQLite。
- `revdeck plugin test` 只做 dry-run 校验，不会修改项目数据库。
- `revdeck plugin commit` 和 `revdeck plugin run --commit` 会先通过 host 验证 manifest、permissions 和 ObjectBatch，再由 host 事务化写入 objects、edges、plugin attributes 和 plugin diagnostics。
- 如果 ObjectBatch 里包含 artifact fact，host 会先创建基础 artifact record，让后续对象可以稳定挂到该 artifact 下。
- fixture replay 不是完整外部进程 sandbox；任意进程执行、public marketplace、签名分发、真实 OS sandbox 和自定义 TUI renderer 都是后续阶段。
