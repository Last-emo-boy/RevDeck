# RevDeck

RevDeck 是一个终端原生、native-first 的逆向分析工作台。它当前聚焦 v0.1 的闭环：导入一个二进制，建立项目数据库，索引 sections、symbols、imports、strings、functions 和关系边，然后在 TUI 中完成 triage、跳转、笔记、finding 和报告导出。

RevDeck 的核心 analyzer、项目模型、TUI 和 plugin runtime 都由 RevDeck 自己拥有。外部逆向工具可以作为能力参照或离线验证参考，但不是运行时依赖，也不是兼容层前提。

## 当前能做什么

- 直接分析 ELF 或 PE/EXE：`revdeck analyze <binary>` 会创建默认项目、注册目标、立即打开 TUI，并在后台继续分析。
- 项目化存储：RevDeck 使用 SQLite 保存 artifacts、analysis runs、objects、edges、findings 和 session memory。
- 自动 triage：Function Radar 会根据危险 import、敏感字符串、调用关系、函数边界置信度等信号给函数排序。
- 三栏 TUI：左侧 Workspace，中央 Main View，右侧 Inspector，底部 Command / Status；后台分析运行时会刷新 Jobs 和对象计数。
- Hex Viewer：在完整索引完成前，也可以用只读 bounded byte window 检查原始 bytes。
- Graph Lab：可以从当前对象打开局部关系图，查看 xrefs、calls、evidence path，以及 native function -> basic block -> instruction 关系。
- Trace、Firmware、Crash 和 Protocol Lab：支持 bounded importer、项目对象写入、TUI 视图、Inspector 证据和 CLI status 输出。
- Command Deck：可以用命令面板查看常用动作、当前对象和命令预览。
- Native Analyzer foundation：导入时会生成 instruction、basic block、CFG edge，以及基础的 native call / branch / RIP-relative string / PE IAT import xref。
- x86-64 typed operands：当前能识别寄存器、内存、relative target 和 immediate operand，覆盖常见 REX.W `mov`、`cmp`、`test`、`call`、`jmp`、RIP-relative load、PE IAT call / thunk。
- 条件来源追踪：basic block 内的 `cmp` / `test` 会链接到后续 conditional branch，Inspector 和 Graph Lab 能显示 branch 依赖的 flag producer。
- 函数发现：除了 symbol 和 entrypoint，native analyzer 会从 executable section 中的 direct `call rel32` 发现保守的 `call_target` 函数候选，并按相邻函数入口/section 末尾收紧函数范围。
- 跨对象跳转：函数、字符串、import、finding 和关系边可以通过当前选择或命令跳转。
- 笔记与分析记忆：可以给当前对象添加 tag、note、rename、status。
- finding 草稿：可以在 TUI 命令栏创建 finding，并把证据对象链接进去。
- 报告导出：支持 JSON 和 Markdown 报告导出。TUI 中 queued 的 export 会在退出 TUI 时写入项目目录。

当前还不做完整反编译、完整指令集覆盖、动态调试、固件解包、完整自动协议恢复和完整插件生态。Trace、Firmware、Crash 和 Protocol Lab 已经有 bounded importer 和 TUI 视图，但当前 xref、函数恢复、trace 语义、crash 解析和协议字段推断仍是保守子集，这些属于后续路线。

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
2. 快速注册 artifact、analysis run 和 `binary.parse` job。
3. 自动进入 TUI，并让后台 worker 完成解析、索引和 Function Radar。

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

一站式命令。创建或打开项目，默认先注册 artifact 并进入 TUI，再由后台 worker 完成解析和索引。使用 `--no-tui` 时保持前台同步执行并打印最终 JSON。

常用参数：

```powershell
revdeck analyze .\sample.exe
revdeck analyze .\sample.exe --no-tui
revdeck analyze .\sample.exe --project .\projects\sample
revdeck analyze .\sample.exe --profile quick
```

`--profile` 控制分析深度：

- `quick`：优先快速 triage，保留 sections、imports、strings、function seeds 和基础 xrefs，跳过 native CFG / instruction 持久化，并在 diagnostics 中记录 `pass_skipped_by_profile`。
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

### `revdeck trace`

导入 JSONL trace，并把 session、event timeline 和可匹配函数写入项目图。

```powershell
revdeck trace import .\case-001 .\fixtures\traces\minimal.jsonl --artifact <artifact-ref> --json
revdeck trace status .\case-001 --artifact <artifact-ref> --limit 20 --json
```

### `revdeck firmware`

导入固件目录 inventory，记录路径、hash、文件类型、嵌套 ELF/PE artifact 占位和 path evidence。

```powershell
revdeck firmware import .\case-001 .\fixtures\firmware\router-root --json
revdeck firmware status .\case-001 <firmware-artifact-ref> --limit 200 --json
```

### `revdeck crash`

导入 crash fixture、sanitizer 输出或泛化 stack trace，规范化 crash report / frame，按 sanitizer class、signal 和调用栈前缀生成 signature，并为高风险 crash class 生成 finding 建议。

```powershell
revdeck crash import .\case-001 .\fixtures\crashes\asan_uaf.json --artifact <artifact-ref> --json
revdeck crash status .\case-001 --artifact <artifact-ref> --limit 20 --json
```

### `revdeck protocol`

导入 bounded 协议样本 JSON，把 sample、message 和 field 写入项目图，记录 payload、schema hypothesis、字段信号，并把 `string_hint` 关联到已索引的 binary string。

```powershell
revdeck protocol import .\case-001 .\fixtures\protocol\login_handshake.json --artifact <artifact-ref> --json
revdeck protocol status .\case-001 --artifact <artifact-ref> --limit 20 --json
```

### `revdeck labs`

列出 RevDeck 内置 Lab registry。这个 registry 是 TUI、CLI、后续 feature flag 和文档共用的 Lab 词汇表。

```powershell
revdeck labs
revdeck labs --json
```

当前 registry 包括：

- Binary Triage Lab：默认闭环，负责导入二进制、索引对象、Function Radar 和证据 triage。
- Workspace/Jobs Lab：只读 pass/job 历史、profile 降级、失败和诊断入口。
- Hex Viewer Lab：只读 byte-first 检查入口，支持在后台分析完成前查看原始 bytes。
- Graph Lab：围绕当前对象查看关系、xref、call、containment 和 evidence path。
- Diff Lab：artifact/project 差异分析，输出可跳转的 delta evidence。
- Trace Lab：JSONL trace 导入、时间线和函数关联。
- Firmware Lab：固件目录 inventory、嵌套 artifact 占位和路径证据。
- Crash Lab：crash log / sanitizer 输出导入、stack frame 规范化和签名聚类。
- Protocol Lab：bounded 协议样本导入、message / field 规范化、schema hypothesis、字段信号和 string hint evidence。
- Plugin Lab：本地插件 manifest、permissions、ObjectBatch dry-run 和 commit 边界。
- Report Lab：finding 校验和 JSON / Markdown evidence bundle 导出。

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

导出 findings 报告，并作为 Report Lab 的 release gate。导出前会校验 finding evidence、证据对象是否仍存在、analysis job 是否失败，以及 plugin evidence 是否能追溯到对应 plugin run。

```powershell
revdeck report .\case-001 --format json --out report.json
revdeck report .\case-001 --format md --out report.md
```

`--format json` 输出 machine-readable release bundle，包含：

- `report`：规范化后的 findings。
- `evidence_objects`：跨 Lab evidence object、artifact identity、display name、地址/大小和 metadata。
- `lab_summaries`：每个 Lab 的 finding 数和 evidence object 数。
- `analysis_jobs`：相关 artifact 的 pass/profile/status/diagnostics 记录。
- `plugin_runs`：plugin id/version、manifest/input/config digest、权限和 diagnostics。
- `validation`：release gate 的 errors 和 warnings。

`--format md` 输出人工审阅报告，包含 `Lab Coverage` 段落和每个 finding 的 evidence 列表。如果没有 `--out`，报告会直接输出到终端。

### `revdeck index <project_dir> [artifact_id]`

当前是保留命令。主要用于后续重新索引流程。

## TUI 布局

RevDeck 的 TUI 是固定的工作台结构：

```text
Cockpit
Workspace | Main View | Inspector
Command / Status
```

- `Cockpit`：显示目标、analysis/import 状态、`jobs=<n>` pass 摘要、当前 view/focus、对象计数和 selected。
- `Workspace`：选择当前分析视图，包括只读的 `Analysis Jobs` 历史 pass 状态视图。
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
| `x` / `H` | 切到只读 Hex Viewer |
| `G` | 切到 Graph Lab / Local Relations |
| `J` | 切到 Analysis Jobs |
| `D` | 切到 Diff Lab |
| `T` | 切到 Trace Lab |
| `W` | 切到 Firmware Lab |
| `C` | 切到 Crash Lab |
| `P` | 切到 Protocol Lab |
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

### Analysis Jobs

Jobs lens 显示当前 artifact 最近的 analysis jobs/pass 历史。它来自项目数据库中的 `analysis_jobs` 表，按 pass、status、profile、progress、objects、diagnostics 和时间展示，用来快速确认 `binary.parse`、`binary.triage`、`binary.cfg`、`binary.dataflow` 等带 Lab 前缀的 pass 结果。默认 `revdeck analyze` 进入 TUI 后，后台分析会让 Jobs lens 和 Cockpit 摘要自动刷新。移动 Jobs 表格行时，右侧 Job Inspector 会显示选中 job 的 ID、run/artifact lineage、limits、timestamps、metadata、parameter snapshot、diagnostic snippets 和 log snippets。

适合做：

- 查看 Cockpit 中 `jobs=<n>`、`skipped=<n>`、`failed=<n>` 的紧凑状态后，进入 Jobs lens 看明细。
- 用 Job Inspector 对照参数和 log snippet，确认失败或跳过来自哪个 pass，而不需要离开 TUI。
- 区分 `failed` 和 `skipped`：`quick` profile 下被跳过的 native CFG 相关 pass 是中性降级，不按失败处理。
- 观察后台 `running` job 何时变成 `succeeded`、`failed` 或 `skipped`。

当前 Jobs lens 是只读状态视图；cancel/rerun 控制和真正任务调度仍是后续阶段。

### Hex Viewer

Hex Viewer 是只读 byte-first 入口。它从 artifact 的 `source_path` 或 `stored_path` 读取 bounded byte window，不会为了绘制界面反复把整个文件载入内存。

适合做：

- 在 `binary.parse` 仍是 `running` 时检查文件头、magic bytes 和可疑 ASCII 片段。
- 对照 Binary Map、Strings、Imports 的索引结果确认原始偏移。
- 分析失败时仍保留最基本的 bytes 检查能力。

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

### Trace Lab

Trace timeline 视图。它显示导入的 trace session 和 event，并把可匹配的事件关联回函数对象。

适合做：

- 用 `T` 快速查看导入 trace 的事件顺序。
- 对照 thread、timestamp、event kind 和 target 信息筛选行为线索。
- 打开 trace event 后在 Inspector 里看关联函数和 finding-link 预览。
- 从动态行为线索跳回 Graph Lab 或 Function Radar。

### Firmware Lab

固件 inventory 视图。它显示固件目录中的文件、类型、大小、hash、可执行标记和嵌套 artifact 关系。

适合做：

- 用 `W` 查看固件文件树导入结果。
- 区分 ELF/PE、脚本、配置、网页资源和 unsupported 文件。
- 从 firmware file Inspector 跳到 nested artifact 或 root firmware artifact。
- 用 path evidence 支撑后续 finding。

### Crash Lab

Crash triage 视图。它显示 crash report、stack frame、signature cluster、sanitizer class、signal 和 top frame。

适合做：

- 用 `C` 查看 ASAN / panic / generic stack trace 导入结果。
- 按 crash class、signal 和 top frame 判断是否值得优先处理。
- 在 Inspector 中查看 stack frame metadata、cluster signature 和关联函数。
- 把高风险 sanitizer crash 作为 finding evidence 继续沉淀。

### Protocol Lab

Protocol schema 视图。它显示导入的协议 sample、message、field、payload 范围、字段类型、entropy、printable ratio、integer value、string hint 和 binary string 关联。

适合做：

- 用 `P` 查看 bounded 协议样本导入结果。
- 对照 message payload、field offset / length 和 schema hypothesis 做人工协议假设。
- 在 Inspector 中查看字段信号，并从 `string_hint` 跳到已索引字符串。
- 把 credential、opcode、length 等字段作为 finding evidence 继续沉淀。

### Report Lab

Report Lab 是所有 Lab 的交付出口。它不重新分析目标，而是把已有 findings、evidence objects、analysis jobs 和 plugin provenance 汇总成可审阅、可自动化检查的报告包。

适合做：

- 在导出前确认每个 finding 都至少有一个 evidence object。
- 查看 `Lab Coverage`，确认 Binary Triage、Diff、Trace、Firmware、Crash、Protocol 和 Plugin evidence 是否进入报告。
- 用 JSON bundle 给 CI、审计脚本或后续工具消费稳定的 evidence/provenance schema。
- 用 Markdown 报告给人工 review、交付说明或 issue 复盘。
- 在 release gate 报错时回到对应 Lab 修正缺失 evidence、失败 job 或 orphan plugin output。

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

1. 在 `Overview` 确认导入状态、对象计数和 Cockpit jobs 摘要；如果对象计数还在增长，说明后台分析仍在运行。
2. 按 `x` 进入 `Hex Viewer`，先看文件头和原始 bytes。
3. 按 `J` 进入 `Analysis Jobs`，确认 `running`、`skipped` 或 `failed` 的具体 pass。
4. 按 `g` 进入 `Triage Board`，看最高优先级 next action。
5. 按 `r` 进入 `Function Radar`，优先看高分函数。
6. 在函数上按 `Enter`，用 `Right` 进入 `Inspector`。
7. 在 Inspector 中用 `Up` / `Down` 选择 evidence，按 `Enter` 跳到字符串或 import。
8. 用 `:xrefs current` 看当前对象关系。
9. 用 `:tag`、`:note`、`:status` 留下分析记忆。
10. 用 `:finding new ...` 和 `:finding link ...` 形成结论。
11. 退出后用 `revdeck report` 导出报告。

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

RevDeck 的路线现在按 Lab registry 组织。Binary Triage Lab 仍是默认入口，其它 Lab 作为共享项目数据库、对象图、analysis jobs、TUI 和报告导出的增量能力逐步落地。

v0.1 目标是 Binary Triage Lab：

- 项目数据库
- ELF / PE 导入
- sections / symbols / imports / strings / functions
- native instructions / basic blocks / CFG edges
- Function Radar
- xrefs / relation navigation
- notes / tags / findings
- TUI 三栏工作台
- JSON / Markdown 报告

已落地的增量 Lab：

- Workspace/Jobs Lab：pass/job 历史、profile 降级、diagnostics/log snippets 和后续控制面。
- Hex Viewer Lab：read-only bounded byte window，支持 fast-open 后立即检查原始 bytes。
- Graph Lab：局部 call graph、xref graph、路径视图和 finding evidence path。
- Diff Lab：版本差异、字符串/import/function diff。
- Trace Lab：JSONL trace 导入和时间线。
- Firmware Lab：固件目录和批量 ELF 分析。
- Crash Lab：ASAN / UBSAN / panic log 聚类。
- Protocol Lab：协议样本、message / field、schema hypothesis 和 string hint evidence。
- Plugin Lab：manifest、permissions、ObjectBatch dry-run/commit、Lab 写权限和 plugin diagnostics。
- Report Lab：跨 Lab evidence bundle、Lab coverage、job diagnostics、plugin provenance 和 release gate。

后续 Lab 方向：

- Native Analyzer：更完整的 instruction coverage、函数恢复、CFG、call graph、数据流和 xref 恢复。
- Plugin ecosystem：导入器、分析器、视图数据、评分器、导出器、签名分发和 marketplace。
- Report automation：更稳定的外部 schema、CI release policy、模板化报告和签名 bundle。

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

[[capabilities]]
id = "report-context"
kind = "report_contributor"
inputs = ["object_batch"]
outputs = ["finding_context"]

[permissions]
artifact_read = ["object_batch_fixture"]
project_write = ["objects", "edges", "attributes", "diagnostics"]
lab_write = ["plugin"]
network = false
process_spawn = false
```

安全边界：

- 默认不授予 network、process spawn、secrets、environment 或文件写权限。
- 插件不能通过 SDK 直接写 SQLite。
- `revdeck plugin test` 只做 dry-run 校验，不会修改项目数据库；输出会包含 ObjectBatch audit，汇总对象类型、edge 类型、attribute namespace、diagnostic severity 和 touched Lab。
- `view_data_provider` 和 `report_contributor` 是 Lab-aware capability；旧的 `lens`、`exporter`、`adapter`、`importer` 等 capability 仍保持兼容。
- 如果 ObjectBatch 包含 `trace`、`firmware`、`crash`、`protocol`、`diff` 或 `plugin` Lab evidence object，manifest 必须声明对应 `lab_write = ["<lab>"]` 或 `lab_write = ["all"]`。
- `revdeck plugin commit` 和 `revdeck plugin run --commit` 会先通过 host 验证 manifest、permissions、Lab 写权限和 ObjectBatch，再由 host 事务化写入 objects、edges、plugin attributes 和 plugin diagnostics。
- 如果 ObjectBatch 里包含 artifact fact，host 会先创建基础 artifact record，让后续对象可以稳定挂到该 artifact 下。
- fixture replay 不是完整外部进程 sandbox；任意进程执行、public marketplace、签名分发、真实 OS sandbox 和自定义 TUI renderer 都是后续阶段。
