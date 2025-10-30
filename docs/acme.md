# ACME 证书申请流程

本文介绍如何使用 sproxy 的内置 ACME 支持，通过新的 `libacme.do` CGI 模块向 Let's Encrypt 等 CA 自动申请证书。

## 启用 ACME 模式

1. 启动服务时增加 `--acme <state-dir>` 选项，并且必须同时提供 `--cert`、`--key`；如需为其他功能保留自签 CA，可一并指定 `--cafile`：

   ```bash
   sproxy --acme /var/lib/sproxy/acme \
     --cert /etc/sproxy/cert.pem \
     --key /etc/sproxy/key.pem \
     ...
   ```

   `state-dir` 用于保存账户信息与挑战缓存，目录会在需要时自动创建。当指定 `--acme` 后，以上三个证书相关文件即使当前不存在也不会导致启动失败。

2. 必须开放公网可访问的 `--http 80` 端口，用于接收 ACME HTTP-01 Challenge（目前不支持 `alpn`、`dns` 等其他验证方式）。

## 可选环境变量

| 变量名 | 说明 | 默认值 |
| --- | --- | --- |
| `SPROXY_ACME_DIRECTORY` | ACME 目录地址，可设为 `staging`/`production` 或自定义 URL | `production`（正式环境） |

建议在正式申请前将 `SPROXY_ACME_DIRECTORY` 设为 `staging` 进行调试。

## 触发证书申请

使用 POST 请求调用 `libacme.do` 并传入目标域名：

```bash
curl -X POST http://<server>/cgi/libacme.do \
     -d 'domain=example.com&contact=mailto:admin@example.com'
```

流程说明：

1. CGI 首先向 ACME 服务创建订单，并获取 HTTP-01 Challenge。
2. sproxy 自动在 `/.well-known/acme-challenge/<token>` 路径下返回 challenge 内容，无需额外挂载静态文件。
3. Challenge 验证通过后，libacme.do 会写入证书与私钥：
   - `--key` 指定路径：PEM 格式私钥
   - `--cert` 指定路径：PEM 格式站点证书
4. 证书写入成功后 CGI 会调用 `flushcert` RPC，sproxy 主进程立即加载新的证书。

若 `--key` 指定的文件已存在，则会直接复用该私钥；只有在文件缺失时才生成新的密钥并写回该路径。

`contact` 参数可选，用于向 CA 提供联系人信息；不提供则默认不上传邮箱。

请求返回 `200 OK` 表示申请成功，`500` 表示 ACME 交互失败，具体错误可在日志中查看。

## 其他注意事项

- `libacme.do` 在 ACME 未启用时会返回 `403`。
- ACME 模式至少需要同时提供 `--cert` 与 `--key`。若指定 `--cafile`、`--cakey`，ACME 不会改动这些文件，它们仍可用于自签证书或 MITM 功能。
- 证书状态与账户密钥会保存在 `--acme` 指定的目录，请确保进程对该目录具有读写权限并做好备份。
- ACME 申请流程通常需要 20–60 秒，期间请勿重复触发。
- 使用 ACME 申请时仍可继续访问原有静态证书，刷新后即时生效。
- 目前仅支持申请单域名证书。
