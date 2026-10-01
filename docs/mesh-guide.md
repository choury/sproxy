# sproxy mesh 组网使用指南

`mesh` 让多台 sproxy 组成一个去中心化网络：凭同一个网络密钥互相发现、互通代理流量，并把请求自动送到最合适的出口节点。设计细节见 [mesh.md](mesh.md)，本文只讲怎么用。

## 概念速览

| 术语 | 含义 |
| :--- | :--- |
| 节点 | 一个启用 mesh 的 sproxy 实例 |
| 入口 | 接受你的请求、把请求送进 mesh 的节点 |
| 出口 | 请求最终离开 mesh、直连目标站的节点 |
| 中继 | 中间转发节点，逐跳自动选择，无需配置 |

一句话工作方式：你在 sites.list 里写"这些流量从某节点出网"（或"自动挑最快出口"），mesh 负责发现节点、探测线路、选择直连还是经中继。

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
| `--mesh-secret=<密钥>` | 必设 | 网络密钥，全网一致。持有者即可入网（凭据用户名固定为 `mesh`） |
| `--mesh-peer=<url>` | 无 | 种子节点地址，可多条。`https://node.example.com[:443]` 或 `quic://node.example.com` |
| `--mesh-relay=on\|off` | on | 是否允许本节点中继他人的 mesh 流量 |
| `--mesh-exit=on\|off` | on | 是否允许本节点做出口（成为 `mesh://auto` 的候选） |
| `--mesh-maxhops=<n>` | 4 | 转发最大跳数 |
| `--mesh-probe-interval=<秒>` | 10 | 线路探测周期 |
| `--mesh-gossip-interval=<秒>` | 30 | 节点表交换周期。**全网应配置一致**，且 ≤ 300 |

启动时会做校验，以下情况直接报错退出：

- 密钥未设置、超长（>127 字符）；
- 节点名含 `/` 或 `+`，或超长（>127 字符，凭据容量限制）；
- 与 `--insecure` 并存（TLS 域名校验是安全根基，不可关闭）；
- `--secret` 里已有名为 `mesh` 的普通用户（与 mesh 凭据冲突）。

## 常用操作

**查看 mesh 状态**

```bash
scli dump mesh
```

输出节点表（每个节点的地址、RTT、探测成功/失败计数、能力位）、当前 auto 出口、各节点的链路状态上报、每个出口的路由选择。SIGUSR1 信号和 `/status` 页面里也包含同样的内容。

**控制本节点角色**

```bash
# 只做入口，不帮别人中继、不做出口
sproxy --mesh=home-a.alice --mesh-secret=... --mesh-relay=off --mesh-exit=off
```

**调试**

```bash
sproxy --debug=mesh ...        # 观察转发决策（dispatch/relay 逐跳日志）
```

## 网络规划建议

- **规模**：设计上限约百节点量级，更多节点需调整 gossip 机制（见 mesh.md §12-5）；
- **密钥**：一个密钥一个信任域。密钥即完全信任——任何持密钥者可入网、被发现、被路由。密钥泄漏只能换新并全网重启（轮换机制见 mesh.md §12-2）；
- **NAT 后节点**：可以做出入口（发起请求、指定出口），但**不能**被别人选为出口或直连（反向通道在规划中）；
- **时钟**：节点需 NTP 对时，偏差超过新鲜度窗口的节点会被静默拒收（mesh.md §12-9）；
- **全部节点 `mesh-gossip-interval` 保持一致**且 ≤300s，否则节奏不一致的节点互相拒收条目。

## 故障排查

| 现象 | 含义 |
| :--- | :--- |
| `[[mesh: unknown node]]` | 策略里写的节点名不在节点表——检查 gossip 是否收敛（`scli dump mesh`）、名字拼写 |
| `[[mesh: no route]]` | 知道这个节点但当前没有可用路径——看链路状态与探测计数 |
| `[[mesh: no exit]]` | `mesh://auto` 没有任何可用出口——检查各节点 `mesh-exit` 与连通性 |
| `[[mesh: loop detected]]` | 出口节点本机策略又把请求送回 mesh——检查出口的 sites.list |
| `[[mesh: hop limit exceeded]]` | 跳数耗尽——通常是环路或 `mesh-maxhops` 过小 |
| `[[mesh: relay disabled]]` | 路径上的中继节点关闭了 `mesh-relay` |
| 探测一直失败 | 看证书域名是否与节点名一致、密钥是否相同、端口是否可达 |

## 已知限制（规划中）

以下能力已设计但未实现（详见 mesh.md §9 Phase 4）：

- 连接数上限（`mesh-max-peers`）与 peer 协议强制 h2/h3；
- NAT 后节点作为出口（反向通道）；
- 逐节点密钥签名（当前为全网共享密钥的单信任域）；
- Web 管理界面、出口失败自动反馈；
- 链路丢包因子（当前路由度量只用 RTT）。
