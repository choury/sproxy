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

   ```url
   http://<本地sproxy>/rproxy/<name>/https://example.com/
   ```

### 浏览器环境准备 (重要)
支持使用 Service Worker 进行内容改写，在使用浏览器访问代理页面前，可以按需激活改写逻辑：

1. 访问本地 `sproxy` 管理页面：`http://<本地地址>/rproxy/sw`。
2. 点击 **Update** 或确保状态显示为 **active**。
3. 此时，浏览器已准备好处理 `/rproxy/` 下的所有内容改写。

> **提示**：Service Worker 一旦注册成功，除非手动注销，否则将持久生效。



### 动态监听方式

运行中的 `sproxy` 可以通过scli的 `listen add [tcp/udp:][ip:]port <rproxy>@[tcp/udp:]host:port` 动态开放新的监听端口，并把进入该端口的流量通过 HTTP `CONNECT` 转发到指定的 `rproxy` 会话。

- `<rproxy>` 为远端注册时使用的名称，若未显式给出协议则默认沿用监听协议。
- `dump listens` 查看当前启用的动态监听，`listen del <id>` 关闭其中一条。

示例：

```bash
> listen add tcp:127.0.0.1:10022 hk@192.168.10.2:22
> dump listens
#1 tcp tcp://127.0.0.1:10022 -> hk@tcp://192.168.10.2:22
```

随后连接本地 `10022` 端口即可通过远端 `hk` 节点访问其 `192.168.10.2:22` 入口。

## 请求与响应流程

1. 客户端访问本地 `/rproxy/<name>/…` 路径。
2. `distribute_rproxy` 解析路径中的目标 URL，重写请求头后经由已注册的 `Rproxy2`/`Rproxy3` 实例发送给远端。
3. 远端节点完成实际的网络请求，并将响应回传给本地 `sproxy`，最终返回给客户端。
4. 特别的，`local` 作为内部实现的一个名称，直接由本机处理，比如 `/rproxy/local/127.0.0.1:8080`

## 30x 跳转与 Cookie 处理

为了确保浏览器在访问代理页面时能正确维持会话和路径上下文，`sproxy` 在服务端对响应头进行了透明改写。

### Location 重写
当后端返回 30x 响应时，`Location` 头会被自动改写为 `/rproxy/<name>/<原始目标>`。
- `https://example.com/foo` → `/rproxy/<name>/https://example.com/foo`
- `/foo` → `/rproxy/<name>/<请求地址>/foo`
这保证了客户端始终停留在 rproxy 路径下，避免意外跳出代理环境。

### Cookie 重写
为了解决 Cookie 路径不匹配导致的 Session 丢失问题，`sproxy` 会拦截并修改 `Set-Cookie` 响应头：
- **Path 改写**：将 `Path=/foo` 改写为 `Path=/rproxy/<name>/<target_base>/foo`。
- **Domain 清除**：移除 `Domain` 属性，强制 Cookie 绑定到当前代理域名，防止跨域设置失败。

## 前端 URL 改写与防逃逸

`sproxy` 采用了 Service Worker (`sw.js`) 和 页面注入脚本 (`inject.js`) 相结合的方式，在客户端实时修正页面中的 URL。

- **Service Worker (`webui/sw.js`)**：
  - 拦截所有 `/rproxy/` 下的请求。
  - 实时解析 HTML/CSS，将 `href`, `src`, `url()` 等资源路径改写为代理路径。
  - 注入 `rproxy_core.js` 和 `inject.js` 到 HTML 头部。

- **页面注入脚本 (`webui/inject.js`)**：
  - Hook `window.fetch`, `XMLHttpRequest`, `window.open` 等 API，确保动态发起的请求也被代理。
  - 拦截 `history.pushState` / `replaceState`，防止 SPA 应用修改地址栏导致路径逃逸。
  - 监听全局点击事件，作为最后的防线修正 `<a>` 标签链接。

- **核心库 (`webui/rproxy_core.js`)**：
  - 包含通用的 URL 上下文解析和改写逻辑，供 `sw.js` 和 `inject.js` 复用。

## 调试与排查

- 访问 `/rproxy/` 会返回当前已注册的远端连接列表，方便确认是否握手成功。
- 日志中会输出 `rproxy: <path> -> <url>`，便于观察路径解析及重写情况。
- 若命名冲突（同名、多次注册、使用 `local` 等保留名），远端会话会被拒绝并在日志中给出原因。

## rproxy-kp (保持源地址)

`rproxy-kp` 是 `rproxy` 模式下的一个增强功能，其核心是 "keep source"（保持源地址）。

### 原理

该功能利用了 Linux 系统提供的 `IP_TRANSPARENT` 套接字选项。

当 `sproxy` 作为 `rproxy` 服务端运行时，如果收到的请求中包含 `X-Forwarded-For` 头部（如果是通过`rproxy`方式转发，`sproxy` 就会自动添加），并且启动时配置了 `--rproxy-kp` 参数，那么 `sproxy` 在向最终目标服务器发起连接时，会尝试将连接的源 IP 地址伪装成 `X-Forwarded-For` 中指定的原始客户端 IP 地址。

这样，对于目标服务器来说，它会认为连接是直接由原始客户端发起的，从而使得 `rproxy` 服务器在网络链路上变得“透明”。

### 使用方法

1. **启用参数**：在启动 `rproxy` 服务端的 `sproxy` 实例时，添加 `--rproxy-kp` 标志。

    ```bash
    # 示例：在本地服务器上启动
    ./sproxy --rproxy=<name> --rproxy-kp <server>
    ```

2. **系统配置**：
    为了让 `IP_TRANSPARENT` 生效，操作系统需要进行相应的**策略路由 (Policy-based Routing)** 配置。你需要使用 `iproute2` 工具包来确保从目标服务器返回的流量能够正确地路由回 `sproxy` 服务器。

    配置主要分为两步：**设置流量标记 (fwmark)** 和 **根据标记配置策略路由**。

    **第一步：设置流量标记 (fwmark)**

    对于 `sproxy` 发出的数据包，你需要为其设置一个标记 (fwmark)，以便后续的路由策略可以识别它们。你有两种方式来设置这个标记：

    **方式一：使用 BPF (推荐)**

    这是更现代且高效的方式。`sproxy` 可以加载一个 BPF 程序，自动为自己创建的套接字打上标记。

    - **启动参数**:
      - `--bpf=<cgroup路径>`: 指定 `sproxy` 进程所在的 cgroup v2 路径，并加载 BPF 程序。
      - `--bpf-fwmark=<标记值>`: 设置要使用的标记值。

    - **示例**:

      ```bash
      # 1. 为 sproxy 创建一个 cgroup
      mkdir /sys/fs/cgroup/sproxy

      # 2. 将当前 shell 放入该 cgroup (sproxy 将继承这个 cgroup)
      echo $$ | tee /sys/fs/cgroup/sproxy/cgroup.procs

      # 3. 启动 sproxy 并启用 bpf 标记
      ./sproxy --rproxy=<name> --rproxy-kp \
               --bpf=/sys/fs/cgroup/sproxy \
               --bpf-fwmark=3333
      ```

    **方式二：使用 iptables**

    这是一个传统且通用的方式。

    - **示例**:

      ```bash
      # 使用 iptables 为 sproxy 用户发出的包打上标记 3333
      iptables -t mangle -A OUTPUT -p tcp -m owner --uid-owner <sproxy_user> -j MARK --set-mark 3333
      ```

    **第二步：根据标记配置策略路由**

    无论使用哪种方式设置了 `fwmark`，接下来的策略路由配置是相同的。

    ```bash
    # 1. 添加策略路由，让所有被标记为 3333 的流量走新的路由表
    ip rule add fwmark 3333 lookup 3333

    # 2. 在新路由表中为所有流量设置默认路由，出口为指定网卡（如果通过localhost连接,则指定lo）
    ip route add local default dev lo table 3333
    ```
