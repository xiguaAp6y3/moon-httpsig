# Contributing

项目托管在 GitHub（`xiguaAp6y3/moon-httpsig`），欢迎通过 Issue 与 PR 贡献。
以下规则适用于所有贡献。

## MoonBit 环境

- MoonBit：优先从 PATH 使用 `moon`，或通过 `MOON_BIN` 环境变量指定
  （含 `wasm-gc` / `js` / `native` 目标）。
- 依赖：`gmlewis/sha256`（已在 `moon.mod` 声明）。

## 本地验证命令

```powershell
moon fmt --check
moon check --target wasm-gc && moon build --target wasm-gc && moon test --target wasm-gc
moon check --target js && moon build --target js && moon test --target js
moon check --target native && moon build --target native && moon test --target native
python scripts\count_code.py
python scripts\generate_rfc_fixtures.py
python scripts\verify_rfc_fixtures.py
```

或一键运行 `scripts\verify_all.ps1`。

## 三目标测试

每次修改必须在三个目标上分别执行 check/build/test，保证 0 warnings、
0 errors。

## 测试规范

- 公共 API 用 `Result[T, HsError]`，测试断言 `stage`/`kind` 而非错误文本。
- 表驱动测试优先；具名测试名称要反映单一关注点。
- 属性测试使用固定种子生成器，三目标结果必须一致。
- 任何密码学/规范边界改动必须补充测试。

## 安全回归要求

- 不得引入 `==` 比较 MAC；统一使用 `constant_time_equal`。
- 不得使公共 API 泄漏密钥、完整签名、完整 Body 或巨大 Header。
- 不得让 keyid 触发任何网络访问。
- 未实现算法必须返回 `AlgorithmNotAllowed`，禁止假验签成功。

## 文档更新规则

- 修改公共 API、CLI 或默认行为时，同步更新 `docs/api-reference.md`、
  `docs/cli-reference.md`、`docs/compliance.md` 与 README 相应章节。

## Structured Field 修改规则

- 修改解析/序列化必须保留顺序语义，并保证 parse→serialize 往返一致。
- 新增语法规格需在 `structured_field_test.mbt` 补表驱动测试。

## 签名基逐字节测试规则

- 签名基测试必须逐字节比对预期字符串（含 LF 与尾部无换行）。
- RFC Appendix B 向量必须保持逐字节通过。

## 禁止项

- 禁止对外部输入使用 `unwrap`（CLI/解析路径）。
- 禁止静默吞掉错误（不得把 `Err` 当作 `Ok` 处理而不记录）。
- 禁止算法假实现。
- 禁止在日志或输出中打印密钥。
- 改动后 `scripts\count_code.py` 的 `total_handwritten_moonbit_lines`
  必须保持在 4000～8000 之间。
