# 本地复现步骤

以下步骤全部在本地完成，无需网络（首次 `moon add` 拉取依赖除外）。

## 环境

- Windows 11，`D:\Moonbit\bin\moon.exe`（MoonBit 0.1.20260713）
- Python 3（`miniconda3` 或系统 Python）
- 项目目录 `D:\Moonbit\projects\project8`

## 步骤

```powershell
# 1. 进入项目
cd D:\Moonbit\projects\project8

# 2. （首次）解析依赖（gmlewis/sha256 已写入 moon.mod，通常无需再执行）
#    moon add gmlewis/sha256

# 3. 格式化检查
moon fmt --check

# 4. 三目标 check / build / test
moon check --target wasm-gc && moon build --target wasm-gc && moon test --target wasm-gc
moon check --target js && moon build --target js && moon test --target js
moon check --target native && moon build --target native && moon test --target native

# 5. 行数统计
python scripts\count_code.py

# 6. RFC fixture 生成与校验
python scripts\generate_rfc_fixtures.py
python scripts\verify_rfc_fixtures.py

# 7. CLI 冒烟
moon run cmd/httpsig-tool -- --help
moon run cmd/httpsig-tool -- rfc-example
# （其余命令见 docs/cli-reference.md）

# 8. 运行示例
moon run examples/sign_request
moon run examples/verify_request
moon run examples/sign_response
moon run examples/multiple_signatures
moon run examples/replay_policy
moon run examples/content_digest_binding

# 9. 包列表
moon package --list
```

## 一键验证

```powershell
powershell -ExecutionPolicy Bypass -File scripts\verify_all.ps1
```

该脚本执行上述全部步骤，任一失败立即停止。

## 已知环境依赖

- `gmlewis/sha256` 用于 SHA-256（Apache-2.0）。下载后在本地 `.mooncakes/`
  缓存，运行时不依赖网络。
- 若某个 target 在本机工具链不完整，不得写成通过；应记录完整错误，其他
  target 独立验证，并标记为环境阻塞。
