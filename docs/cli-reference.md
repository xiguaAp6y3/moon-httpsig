# CLI 参考

`httpsig-tool` 运行方式：`moon run cmd/httpsig-tool -- <command> [flags]`。
所有输出为单行稳定 JSON。错误输出：

```json
{"ok": false, "error": {"stage": "...", "kind": "...", "offset": 0, "context": "..."}}
```

## 命令

### --help / --version

```sh
moon run cmd/httpsig-tool -- --help
moon run cmd/httpsig-tool -- --version
```

### parse-input

解析 `Signature-Input` 字段。

```sh
moon run cmd/httpsig-tool -- parse-input --signature-input 'sig1=("@method" "@target-uri");created=1618884473;keyid="k1"'
# {"ok":true,"labels":["sig1"],"count":1}
```

### parse-signature

解析 `Signature` 字段。

```sh
moon run cmd/httpsig-tool -- parse-signature --signature 'sig1=:dGVzdA==:'
```

### parse-accept

解析 `Accept-Signature` 字段。

```sh
moon run cmd/httpsig-tool -- parse-accept --accept-signature 'a=("@method");created;keyid="k"'
```

### build-base

用给定的消息与 `Signature-Input` 构造签名基。**只表示构造，不代表验签。**

```sh
moon run cmd/httpsig-tool -- build-base \
  --method POST --path /foo --header 'content-type=application/json' \
  --signature-input 'sig1=("@method" "content-type");created=1618884473;keyid="k1";alg="hmac-sha256"'
```

### sign-hmac

HMAC-SHA256 签名请求。**禁止输出 secret**。

```sh
moon run cmd/httpsig-tool -- sign-hmac \
  --method POST --path /foo --header 'content-type=application/json' \
  --secret-hex 736563726574 --keyid k1 --created 1700000000 \
  --component @method --component content-type
```

### verify-hmac

验证 HMAC-SHA256 签名。

```sh
moon run cmd/httpsig-tool -- verify-hmac \
  --method POST --path /foo --header 'content-type=application/json' \
  --secret-hex 736563726574 --keyid k1 --now 1700000000 \
  --signature-input 'sig1=("@method");created=1700000000;keyid="k1";alg="hmac-sha256"' \
  --signature 'sig1=:...:'
```

### inspect

只解析并列出标签与覆盖组件。**只代表解析，不代表验签。**

```sh
moon run cmd/httpsig-tool -- inspect --signature-input 'sig1=("@method");created=1618884473;keyid="k1"'
```

### check-policy

解析并做策略检查（expires≥created、keyid 存在、required component）。

```sh
moon run cmd/httpsig-tool -- check-policy \
  --signature-input 'sig1=("@method");created=1618884473;keyid="k1"' \
  --required-component @method
```

### rfc-example

执行真实的 RFC 9421 B.2.5 HMAC 示例并比对期望 MAC。

## 标志

| 标志 | 含义 |
| --- | --- |
| `--method` | HTTP 方法（默认 GET） |
| `--scheme` | scheme（默认 https） |
| `--authority` | authority（默认 example.com） |
| `--path` | 路径（默认 /） |
| `--query` | query（缺省为无） |
| `--header NAME=VALUE` | 追加一个 Header，可重复 |
| `--signature-input` | Signature-Input 字段值 |
| `--signature` | Signature 字段值 |
| `--accept-signature` | Accept-Signature 字段值 |
| `--component NAME` | 覆盖组件，可重复（如 `@method`、`content-type`） |
| `--keyid` | 密钥标识 |
| `--secret-hex` | 共享密钥的十六进制 |
| `--created` / `--expires` | 时间戳 |
| `--nonce` / `--tag` | 防重放/标签 |
| `--now` | 验证时的时间 |
| `--label` | 签名标签（默认 sig1） |
| `--required-component` | check-policy 的必需组件 |

## 安全

- 外部输入不使用 `unwrap`，非法输入不 panic，错误退出码非零（通过 abort 触发）。
- secret 不进入日志与输出。
- JSON 字符串正确转义。
