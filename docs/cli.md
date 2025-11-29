# scli 与 RPC 说明

`scli` 是 `sproxy` 的交互式命令行客户端，通过内置 JSON-RPC 与运行中的实例通信，可进行策略管理、状态查看与动态监听配置。本文件同时给出 RPC 原理，方便自定义工具接入。

## 启动
- 构建后生成 `scli` 可执行文件（随 `cmake && make` 一同产出）。
- 默认连接 `/var/run/sproxy.sock`，不存在时回退 `/tmp/sproxy.sock`。
- 使用 `-s/--socket` 显式指定：`./scli -s /path/to/sproxy.sock` 或 `./scli -s tcp:<host>:<port>`，IPv6 以 `tcp:[::1]:<port>` 形式。
- 支持 Linux 抽象 Socket：`-s @sproxy`。

启动成功后会提供基于 GNU Readline 的补全与历史记录。

## 常用命令
- `adds <strategy> <host> [ext]`：为目标域名添加策略（策略名称支持补全，如 `local`、`proxy`、`rewrite` 等）。
- `dels <host>`：删除域名策略。
- `test <host>`：查看当前匹配到的策略。
- `flush <dns|cgi|strategy|cert>`：刷新缓存或热加载证书。
- `dump <status|dns|sites|usage|hookers|listens>`：查看当前状态、DNS 缓存、站点策略列表、内存占用、Hook 状态或动态监听列表。
- `switch <proxy>`：切换上游代理目标，形如 `http://1.2.3.4:8080`。
- `debug <enable|disable> <module>`：打开/关闭模块调试日志。
- `kill <hex_addr>`：终止指定连接（地址来源于 `dump status` 输出）。
- `hooker add <addr_hex> <lib>` / `hooker del <addr_hex>`：动态加载或卸载 Hook。
- `listen add [tcp/udp:][ip:]port <rproxy>@[tcp/udp:]host:port`：新增 rproxy 动态监听，示例：`listen add tcp:127.0.0.1:10022 hk@192.168.10.2:22`。
- `listen del <id>`：删除指定动态监听。
- `help [cmd]`：查看命令帮助；`exit` 退出。

## 典型操作示例
```bash
$ ./scli
connect to socket: /var/run/sproxy.sock
> adds proxy example.com
> test https://example.com/
proxy
> dump status
total req: 10 ...
> flush dns
```

## RPC 原理与协议
`scli` 与 CGI 都复用同一套轻量 JSON-RPC 接口。若需编写自定义客户端，可按以下规则实现：

### 帧格式
- 每个请求/响应以 **4 字节大端长度** 开头，后跟 UTF-8 JSON 文本。
- 请求体必须包含 `method` 字段，其余字段按具体方法携带。
- 成功时返回各方法定义的字段，失败时包含 `error` 字段。

示例：
```json
// 请求
{"method":"DumpStatus"}

// 响应
{"status":"total req: 10 ..."}
```

### 方法列表
- 策略：`AddStrategy(host,strategy,ext) -> ok`，`DelStrategy(host) -> ok`，`TestStrategy(host) -> strategy`，`DumpStrategy() -> strategies[]`。
- 刷新：`FlushCgi()`，`FlushDns()`，`FlushStrategy()`，`FlushCert() -> ok`。
- 上游：`SetServer(server) -> ok`，`GetServer() -> server`。
- 状态：`DumpStatus() -> status`，`DumpDns() -> dns_status`，`DumpMemUsage() -> mem_usage`，`DumpHooker() -> hookers`。
- 认证与调试：`Login(token,source) -> ok`，`Debug(module,enable) -> ok`。
- 连接管理：`killCon(address_hex) -> ok`。
- Hook：`HookerAdd(hooker_hex,lib) -> ok`，`HookerDel(hooker_hex) -> ok`。
- 动态监听：`ListenAdd(bind,target) -> ok`，`ListenDel(id) -> ok`，`ListenList() -> listeners[]`。详见 `docs/rproxy.md` 中的监听用例。
