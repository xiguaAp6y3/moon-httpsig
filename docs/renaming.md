# 模块重命名记录

本项目正式模块命名空间已从临时命名空间 `localdev/moon-httpsig` 统一修改为
**`xiguaAp6y3/moon-httpsig`**（对应 GitHub 仓库
`xiguaAp6y3/moon-httpsig`）。

## 已修改的文件

| 文件 | 改动 |
| --- | --- |
| `moon.mod` | `name = "localdev/moon-httpsig"` → `name = "xiguaAp6y3/moon-httpsig"` |
| `cmd/httpsig-tool/moon.pkg` | `import { "localdev/moon-httpsig" @hsig }` → `"xiguaAp6y3/moon-httpsig"` |
| `adapters/http11/moon.pkg` | 同上 |
| `examples/*/moon.pkg`（6 个） | 同上 |
| `README.md`、`CHANGELOG.md` | 提及旧命名空间处已更新为 `xiguaAp6y3/moon-httpsig` |

替换后三目标 `check`/`test` 全部通过，仓库中不再有需要运行时使用的
`localdev/moon-httpsig` 引用。本文件保留了旧命名空间的说明，仅作为历史记录。

## 历史背景

立项阶段使用临时模块名 `localdev/moon-httpsig`，且不填写 repository、author、
maintainer、email 等身份信息。模块命名空间确定后统一替换；此后本文件的角色
从“重命名说明”变为“重命名记录”。

## 约束

- 重命名后不得遗留任何需要运行时使用的 `localdev/moon-httpsig` 引用；
- 不得填写未确定的未来账号或邮箱；
- 除模块名本身外，本阶段不引入与命名空间无关的大范围改动。
