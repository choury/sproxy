# sproxy mesh 组网使用指南

`mesh` 让多台 sproxy 组成一个去中心化网络：凭同一个网络密钥互相发现、互通代理流量，并把请求自动送到最合适的出口节点。

## 概念速览

| 术语 | 含义 |
| :--- | :--- |
| 节点 | 一个启用 mesh 的 sproxy 实例 |
| 入口 | 接受你的请求、把请求送进 mesh 的节点 |
| 出口 | 请求最终离开 mesh、直连目标站的节点 |
| 中继 | 中间转发节点，逐跳自动选择 |

一句话工作方式：在 sites.list 里写"这些流量从某节点出网"（或"自动挑最快出口"），mesh 负责发现节点、探测线路、选择直连还是经中继。出口节点对 mesh 流量不套本地策略，直接出网。

除了 sites.list，客户端也可以在代理凭据里直接指定 mesh 目标，用户名写成 `用户+目标名:密码`：

```bash
curl -x client+node-b.example.com:pass@127.0.0.1:8111 http://example.com/
```

目标名（identifier）是一个统一命名空间，按 **alias > rproxy 后端 > mesh 节点** 的优先级解析（本地配置可覆盖同名 mesh 节点）；`auto` 同样可用（如 `client+auto:pass`）。任何通过本节点认证的用户都可以这样触发 mesh 路由。

## 快速开始

场景：家里有台 NAT 后的机器 A，两台有公网域名的服务器 B、C。

**第 1 步：在公网节点上启用 mesh**（B、C 各自机器）

```bash
sproxy --bind=0.0.0.0:443:ssl \
       --cert=node-b.example.com.crt --key=node-b.key \
       --mesh=node-b.example.com \
       --mesh-secret=<自己定一个网络密钥>
```

要求：
- 节点名必须与证书覆盖的域名一致（TLS 域名校验是防冒充的根本）；
- 证书可手动配置，或用 ACME 自动申请（见 [acme.md](acme.md)）；
- 证书由 Public CA 签发即可，无需自建 CA。

**第 2 步：在 NAT 后节点上接入**（机器 A）

```bash
sproxy --mesh=home-a.alice \
       --mesh-secret=<同一个网络密钥> \
       --mesh-peer=https://node-b.example.com:443 \
       --mesh-peer=https://node-c.example.com:443
```

- NAT 后节点不需要证书和公网地址，只需能主动外连；
- `mesh-peer` 只需配一个种子，其余节点会自动发现；多配几个只是加快首次收敛。

**第 3 步：在 A 的 sites.list 里指定哪些流量走 mesh**

```text
us          alias  mesh://node-b.example.com
google.com  proxy  @us
netflix.com proxy  mesh://auto
```

- `mesh://<节点名>`：指定出口节点（语义是"从这台机器出网"）；
- `mesh://auto`：自动在所有可用出口里挑当前路径最优的，出口故障会自动切换；
- 与普通策略语法完全兼容，可以用 alias 管理，详见 [strategy.md](strategy.md)。

完成。A 上的客户端照常把 A 当代理用即可。

## 配置项

| 选项 | 默认 | 说明 |
| :--- | :--- | :--- |
| `--mesh=<节点名>` | 无 | 启用 mesh。可直连节点的名字须与其证书域名一致；NAT 后入口节点任意唯一名（建议带组织前缀防撞名，如 `home-a.alice`） |
| `--mesh-secret=<密钥>` | 必设 | 网络密钥，全网一致。持有者即可入网；mesh 节点间逐跳转发使用 `mesh` 用户的凭据 |
| `--mesh-peer=<url>` | 无 | 种子节点地址，可多条。`https://node.example.com[:443]` 或 `quic://node.example.com` |
| `--mesh-relay=on|off` | on | 宣告中继能力；未宣告 relay 的节点不作为路由中间跳 |
| `--mesh-exit=on|off` | on | 宣告出口能力并允许本节点做出口（成为 `mesh://auto` 的候选） |

路由计算的最大路径跳数（10）、线路探测周期（10s）、节点表交换周期（30s）为编译内置值，不提供配置项；测试套件用环境变量 `SPROXY_MESH_PROBE_INTERVAL`/`SPROXY_MESH_GOSSIP_INTERVAL`（秒）加速收敛，非部署用途。

启动时会做校验，以下情况直接报错退出：

- 密钥未设置、超长（>127 字符）；
- 节点名含 `/` 或 `+`，或超长（>127 字符，凭据容量限制）；
- 与 `--insecure` 并存（TLS 域名校验是安全根基，不可关闭）；
- `--secret` 里已有名为 `mesh` 的普通用户（与 mesh 凭据冲突）；
- 能力全开却没有任何可连接的监听（ssl/quic/http）——宣告了角色就必须可达，改关 `--mesh-exit/--mesh-relay` 做纯入口。

## 常用操作

**查看 mesh 状态**

```bash
scli dump mesh
```

输出节点表（每个节点的地址、RTT、探测成功/失败计数、能力位）、当前 auto 出口、各节点的链路状态上报、每个出口的路由选择。SIGUSR1 信号和 `/status` 页面里也包含同样的内容。

**控制本节点角色**

```bash
# 只做入口，不帮别人中继、不做出口（全网不会向它发起任何探测或 gossip 连接）
sproxy --mesh=home-a.alice --mesh-secret=... --mesh-relay=off --mesh-exit=off
```

**调试**

```bash
sproxy --debug=mesh ...        # 观察转发决策（dispatch 逐跳日志）
```

## 网络规划建议

- **规模**：设计上限约百节点量级，更多节点需调整 gossip 机制；
- **密钥**：一个密钥一个信任域。密钥即完全信任——任何持密钥者可入网、被发现、被路由。密钥泄漏只能换新并全网重启；
- **NAT 后节点**：可以做出入口（发起请求、指定出口），但**不能**被别人选为出口或直连（反向通道在规划中）；
- **入口节点（能力全关）**：控制面零入向连接的代价是纯 gossip 下游——它不转发节点表与链路状态，两个分区若仅靠入口节点相连则互相不可见；
- **时钟**：节点需 NTP 对时，偏差超过新鲜度窗口的节点会被静默拒收。

## 故障排查

| 现象 | 含义 |
| :--- | :--- |
| 404 `[[can't find backend]]` | 目标名在 alias、rproxy 后端、mesh 节点表三处都不存在——检查名字拼写、gossip 是否收敛（`scli dump mesh`） |
| `[[mesh: no route]]` | 知道这个节点但当前没有可用路径——看链路状态与探测计数 |
| `[[mesh: no exit]]` | `mesh://auto` / `auto` 目标没有任何可用出口——检查各节点 `mesh-exit` 与连通性 |
| 探测一直失败 | 看证书域名是否与节点名一致、密钥是否相同、端口是否可达 |

## 已知限制（规划中）

以下能力暂未实现：

- 连接数上限（`mesh-max-peers`）与 peer 协议强制 h2/h3；
- NAT 后节点作为出口（反向通道）；
- 逐节点密钥签名（当前为全网共享密钥的单信任域）；
- Web 管理界面、出口失败自动反馈；
- 链路丢包因子（当前路由度量只用 RTT）。
