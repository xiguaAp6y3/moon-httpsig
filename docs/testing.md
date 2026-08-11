# 测试规范

## 运行

```sh
moon test                       # 默认目标
moon test --target wasm-gc
moon test --target js
moon test --target native
```

## 组织

- 每个功能模块有对应的 `*_test.mbt`。
- 公共测试辅助在 `test_support.mbt`；确定性生成器在 `test_generator.mbt`。
- RFC 逐字节测试在 `rfc9421_examples_test.mbt`，数据在 `testdata/rfc9421`。

## 规范

1. 公共 API 必须用 `Result[T, HsError]` 返回错误；测试用 `match` 断言
   `stage`/`kind`，不要断言错误消息文本。
2. 表驱动测试：一个具名测试可包含多个表格案例；不要把几十种无关功能塞进
   一个名字。
3. 属性测试使用固定种子 `Prng`，三目标结果必须一致。
4. 密码学向量（HMAC、签名基）必须逐字节比对，不允许忽略空格。
5. 负面用例必须覆盖格式错误、策略拒绝、密码学失败与资源上限。
6. 任何改动后运行三目标 `check`/`build`/`test`，保证 0 warnings、0 errors。

## 覆盖率目标

- 具名测试 ≥ 100（当前 179）；
- 表格案例 ≥ 200（当前超过 200）；
- 确定性属性测试 ≥ 1000 组（当前 1400）；
- RFC HMAC 与签名基示例全部逐字节通过。
