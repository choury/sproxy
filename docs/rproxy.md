# rproxy 模式概览

`rproxy` 提供了一种将远端 HTTP/2 / HTTP/3 会话桥接到本地 `sproxy` 上的方式。其核心思想是把远端出口代理暴露为一组以 `/rproxy/<name>/…` 开头的本地路径，使得本地访问者可以透明地经由远端节点转发请求。

- **客户端（Rguest2/Rguest3）**：以 HTTP/2（可选 HTTP/3）连接远端 `Server`，并使用 `GET /rproxy/<name>` 作为握手，向本地注册一个名为 `<name>` 的远端会话。
- **服务端（Rproxy2/Rproxy3）**：在 `sproxy` 服务端接收注册，将 `<name>` 映射到实际的远端连接，并通过 `distribute_rproxy` 将本地请求转发到对应远端。
- **统一入口**：访问形如 `/rproxy/<name>/<scheme>://host[:port]/path` 的 URL 即可通过远端代理发起请求；特殊的 `/rproxy/<name>/` 会被自动补全尾随 `/` 并输出目录索引。

## 启动方式

1. 在需要作为出口的远端节点上：
   ```bash
   ./sproxy --server=<远端监听地址> --rproxy=<name>
   ```
   - `--rproxy` 会启用专用模式，仅保留远端到本地的桥接功能。
   - 名称 `<name>` 会出现在路径 `/rproxy/<name>/…` 中，用来区分多个远端。

2. 在本地节点上保持常规 `sproxy` 运行并开放静态文件目录，远端注册成功后，即可通过浏览器或工具访问：
   ```
   http://<本地sproxy>/rproxy/<name>/https://example.com/
   ```

## 请求与响应流程

1. 客户端访问本地 `/rproxy/<name>/…` 路径。
2. `distribute_rproxy` 解析路径中的目标 URL，重写请求头后经由已注册的 `Rproxy2`/`Rproxy3` 实例发送给远端。
3. 远端节点完成实际的网络请求，并将响应回传给本地 `sproxy`，最终返回给客户端。
4. 特别的，`local` 作为内部实现的一个名称，直接由本机处理，比如 `/rproxy/local/127.0.0.1:8080`

## 30x 跳转处理

当后端返回 30x 响应时，如果 `Location` 为绝对地址（如 `https://example.com/foo` 或 `/foo`），会导致浏览器跳出 `/rproxy/<name>/` 前缀。\
自 `rproxy` 重写机制引入后：

- 仅在rproxy请求中（通过`Rproxy-Name`头判断）生效。
- 将 `Location` 重写为 `/rproxy/<name>/<原始目标>`，例如：
  - `https://example.com/foo` → `/rproxy/<name>/https://example.com/foo`
  - `/foo` → `/rproxy/<name>/<请求地址>/foo`
- 这样保证客户端始终留在 rproxy 路径下，避免意外跳出。

## 调试与排查

- 访问 `/rproxy/` 会返回当前已注册的远端连接列表，方便确认是否握手成功。
- 日志中会输出 `rproxy: <path> -> <url>`，便于观察路径解析及重写情况。
- 若命名冲突（同名、多次注册、使用 `local` 等保留名），远端会话会被拒绝并在日志中给出原因。
