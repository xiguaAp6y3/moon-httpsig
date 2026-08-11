# 后期重命名说明

本阶段使用临时模块名 `localdev/moon-httpsig`，且不填写 repository、author、
maintainer、email、homepage 等身份信息。**后期身份确定后**需要统一替换命名
空间；届时再填写对应账号与邮箱（本阶段不填写，也不得在最终报告声称已完成
身份信息）。

## 需要修改的文件

| 文件 | 改动 |
| --- | --- |
| `moon.mod` | `name = "localdev/moon-httpsig"` → 新的 `owner/name`；视需要补充 repository/homepage/author/maintainer/email |
| `moon.pkg` | `"localdev/moon-httpsig"` 引用（根包内嵌，通常无显式引用） |
| `cmd/httpsig-tool/moon.pkg` | `import { "localdev/moon-httpsig" @hsig }` → 新包名 |
| `examples/*/moon.pkg` | 同上 |
| `adapters/http11/moon.pkg` | 同上 |
| `docs/*.md`、`README.md` | 提及 `localdev/moon-httpsig` 处 |
| `THIRD_PARTY_NOTICES.md` | 如适用 |

## 替换方式

在根目录执行批量替换后，运行三目标验证：

```powershell
# 示例（identity 替换为新的 owner/name）
# 先全局搜索 "localdev/moon-httpsig"，确认全部出现位置
moon check --target wasm-gc && moon test --target wasm-gc
moon check --target js && moon test --target js
moon check --target native && moon test --target native
```

## 约束

- 重命名后不得遗留任何 `localdev/moon-httpsig` 引用；
- 不得填写未确定的未来账号或邮箱；
- 重命名不属于本阶段任务。
