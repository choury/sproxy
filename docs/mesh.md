# sproxy mesh 组网设计

mesh 是 sproxy 的去中心化多节点协作能力：一组 sproxy 实例凭借同一个网络密钥（mesh secret）自组织成网，互相发现、互通有无，并把代理请求沿当前最优线路送达指定出口节点。

- **去中心化**：节点完全对等，无中心服务器。任何节点只要持有网络密钥即可入网，节点间通过 gossip 同步节点表。
- **节点感知**：节点表经 gossip 自动传播，每个节点都掌握全网节点及其能力（可否做出口/中继）。
- **自动选路**：分两层——
  - **路径层（永远自动）**：到出口节点走直连还是经中继、经谁中继，由各节点根据实时探测的 RTT/丢包逐跳决策；
  - **出口层（两种语法并存）**：`mesh://<节点名>` 显式指定出口（策略意图，如"要美国 IP"）；`mesh://auto` 在所有可做出口的节点里自动挑当前最优。

设计原则：**不新造传输层，一切节点间通信复用现有代理转发语义**。mesh 节点之间的连接就是普通的 h2/h3 代理连接，控制面消息是这些连接上的 HTTP 请求，数据面转发就是代理级联。加密与身份直接使用现有 TLS/QUIC + Public CA 证书体系。

## 1. 术语与角色

| 术语 | 含义 |
| :--- | :--- |
| **节点（node）** | 一个启用 mesh 的 sproxy 实例。可直连节点的名字必须是该节点 TLS 证书覆盖的域名（如 `node-us.example.com`），节点名即节点在网络中的唯一标识；NAT 后入口节点的命名约定见第 8 节。 |
| **网络密钥（mesh secret）** | 所有节点共享的准入密钥。持有者即可入网、使用网络与被网络服务。 |
| **peer 连接** | 两个节点间的长连 TLS(h2) 或 QUIC(h3) 连接，同时承载控制面消息和转发的代理请求。 |
| **入口（entry）** | 接受客户端请求、把请求送进 mesh 的节点。 |
| **出口（exit）** | 请求最终离开 mesh、直连目标的节点。能力位 `exit` 声明。 |
| **中继（relay）** | 转发他人 mesh 流量的中间节点。能力位 `relay` 声明。 |
| **节点表（node table）** | 全网节点信息的本地视图，经 gossip 维护。 |
| **链路状态（link state）** | 各节点上报的自己到各 peer 的 RTT/丢包度量，是路由计算的输入。 |

同一个节点可以同时是入口、中继和出口。`mesh-relay off` 的节点不转发他人流量；`mesh-exit off` 的节点不出现在 `mesh://auto` 的候选里。

## 2. 身份与准入

### 2.1 节点身份

节点身份 = **节点名（域名）+ Public CA 签发的证书**，二者强绑定：

- 需要被直连的节点必须有公网可达的监听地址（现有 `bind ... ssl|quic`）和有效证书（手动 `--cert/--key`、`--certs` SNI 目录或 ACME 自动申请均可，见 [acme.md](acme.md)）。
- 发起 peer 连接的一方按域名做标准 TLS 校验：客户端侧由 `X509_VERIFY_PARAM_set1_host` 做域名钉扎（`src/prot/sslio.cpp`，QUIC 同），**证书不匹配节点名的节点无法被直连**。前提是所有节点不得开启 `--insecure`（`ignore_cert_error` 会旁路校验）——postConfig 校验拒绝 mesh 与 insecure 并存。
- **注意钉扎对象的错位风险**：现有 TLS 栈把拨号主机名、SNI、证书校验名绑在同一个 `Destination.hostname` 上（无独立的校验名字段）。若节点表允许 addrs 主机名 ≠ 节点名，投毒 addrs 即可把流量劫持到攻击者自己的合法证书域名上（钉扎的是攻击者域名，校验照样通过）。因此**节点表条目强制约束：addrs 中每个 URL 的主机名必须等于节点名**（addrs 只用于声明同一域名的不同 scheme/端口；一个域名的多 IP 解析本就由 DNS 承担）。条目校验不满足即拒绝入表。给 RWer 增加独立 verify-name 覆盖（pin 节点名、拨号 addrs）作为 Phase 4 的增强，首期不做。
- NAT 后的节点（无公网地址、无证书）只能主动外连，作为纯入口使用（见 5.4）。NAT 节点无法被唯一验证身份，命名采用 `组织前缀-名字` 约定（如 `home-a.alice`）降低无恶意重名概率；gossip 发现同名不同签名的条目交替出现时按冲突告警（见第 11 节残余风险）。

### 2.2 准入认证

- 凭据：user 固定为 `mesh`，pass 为 mesh secret，走现有 `Proxy-Authorization: Basic` 通道（`encodeCredit`/`decodeauth`），装载进现有 secrets 体系（`addsecret`）。两种形态：**控制面**请求用 `mesh:<secret>`（无 identifier）；**数据面**转发请求用 `mesh+<出口节点名>:<secret>`（`user+identifier:pass` 形态，identifier 承载最终出口名，与 rproxy backend 的 identifier 用法同构）。若站点已有名为 `mesh` 的普通代理用户会与之冲突，postConfig 检测并报错。
- **mesh 凭据与普通代理用户凭据（`--secret`）分离**：`X-Mesh-*` 转发语义与 `/mesh/*` 控制面仅对 user 为 `mesh` 且校验通过的凭据生效；普通代理用户不能借用 mesh 头把流量送进 mesh，也不能拉取节点表。
- 传输加密由 TLS/QUIC 提供，Basic 明文密码不出节点间连接（与现有上游代理认证同一威胁模型）。
- gossip 节点表条目带独立 HMAC 签名：`HMAC-SHA256(mesh_secret, 规范化串)`，规范化串的精确字节格式见 5.1。**不复用 `gen_token`/`checktoken`**——其密钥取"证书私钥优先"且验证方存在 default key 时早退，节点证书配置不一致时会互相验签失败；mesh 签名的密钥固定为 mesh secret。

### 2.3 信任模型（明确边界）

单一信任域设计：所有持密钥者地位平等，密钥即完全信任。由此产生的残余风险及对策见第 11 节。需要更强隔离（防成员投毒、成员级撤销）时，升级路径是逐节点 Ed25519 密钥对签名节点条目（节点 ID = 公钥指纹），条目编码预留算法标识字段，不在首期实现。

## 3. 总体架构

```
                    ┌────────────────────────────────────────────┐
                    │              mesh 节点（每个 sproxy 实例）   │
                    │                                            │
 客户端 ──代理请求──▶│ distribute()                               │
                    │   ├─ 命中 mesh:// 策略 ──▶ 入口处理          │
                    │   └─ 携带 X-Mesh-* 头 ──▶ 中继/出口处理      │
                    │                                            │
                    │ MeshManager（src/mesh/）                    │
                    │   ├─ 节点表 + gossip（控制面）               │
                    │   ├─ 探测调度 + 度量（EWMA）                 │
                    │   └─ 路由计算（Dijkstra + 逐跳决策 + 防环）  │
                    │                                            │
                    │ peer 连接 = 现有 Proxy2(h2) / Proxy3(h3)     │
                    │ 控制面消息 = peer 连接上的 /mesh/* HTTP 请求  │
                    │ 数据面转发 = 现有代理级联（CONNECT + chain）  │
                    └────────────────────────────────────────────┘
```

控制面与数据面同走一条 peer 连接，不单独建连。节点间的 peer 连接由 `MeshManager` 构造 `Destination`（`https://<节点名>:443`，URL userinfo 内嵌 mesh 凭据主体）经现有 `Host::distribute` 建立并复用：`spliturl` 解析 userinfo 进 `dest.credit`，`distribute()` 删除旧 `Proxy-Authorization` 后会从 `dest.credit` 经 `encodeCredit` 重建——**凭据主体（user/pass）在级联每一跳自动携带**；数据面请求的 identifier（每请求的最终出口名）不在此列，需在入口/中继代码里逐请求构造 `Credit` 后 `encodeCredit`。

MeshManager 发起控制面请求属于**内部请求管道**，现有代码无先例（全仓库仅 `distribute()` 末尾一处调用 `Host::distribute`）：构造 `HttpReqHeader`（absolute-form，`Dest=http://localhost/mesh/...`）+ `MemRWer`，**直接调 `Host::distribute(req, dest, rw)`**（dest 为 peer 地址），绕过本机 `distribute()`——否则 `localhost` 目标会被本机 local 策略短路、根本出不了网。request_id 记账（`nextId()`）与 MemRWer 生命周期由 MeshManager 自持。断线按指数退避（1s→32s，运行 30 分钟后重置）重连；退避状态必须 per-peer（不能复刻 `Rguest2` 的 static `next_retry`，那是全实例共享的）。

注：`responsers` 连接池的 key（`dumpDest(dest)+'@'+protocol`）不含凭据，同一 dest 的 mesh peer 连接与普通上游连接会合并复用。功能上无害，但观测时"peer 连接"与"普通上游连接"不可区分，dump 输出需接受这一混淆。

## 4. 数据面设计

### 4.1 策略语法与出口选择

mesh 目标以 `mesh://` scheme 出现在策略 ext 里，与现有 alias/proxy 语法无缝组合：

```text
# sites.list
us          alias  mesh://node-us.example.com   # 显式出口
best        alias  mesh://auto                  # 自动出口
google.com  proxy  @us                          # 走美国出口
netflix.com proxy  @best                        # 走当前最优出口
*.example.com proxy mesh://node-hk.example.com  # 也可以直接写，不必经过 alias
```

- **显式出口** `mesh://<节点名>`：策略意图，mesh 只优化"怎么到它"。出口节点失联时请求沿现有代理错误路径报 `[[connect failed]]`（503），不做隐式切换——换了出口就换了出口 IP，静默切换往往不是用户想要的。
- **自动出口** `mesh://auto`：在所有 `exit` 能力节点中选路径总代价最小者；节点失联/劣化时后续请求自动切换（在滞回窗口约束下，见 6.3）。**本节点自身不参与 auto 候选**——想直连就写 `direct`，写 `mesh://auto` 的语义就是"出网"。
- `mesh://` 不经过 `parseDest`——它对未知 scheme 直接报错返回（`config.c` `parseDestPath`），必须在 `distribute()` 的 `Strategy::proxy` 分支里于 `parseDest` **之前**拦截；节点表里存的真实地址是普通 URL（`https://`/`quic://`），后续照旧走 `parseDest` + `Host::distribute`。

### 4.2 转发流程

一次 `google.com proxy @us`（出口为 node-us，路径 A→B→node-us）的完整流程：

```
client              A(入口)                 B(中继)                node-us(出口)
  │                 │                       │                       │
  │─CONNECT────────▶│  策略命中 mesh://node-us                       │
  │                 │  先 del 客户端自带 X-Mesh-* 头                  │
  │                 │  出口=node-us, 路由: 下一跳 B                  │
  │                 │─CONNECT google.com:443▶│                       │
  │                 │  Proxy-Authorization: Basic base64(mesh+node-us:***)
  │                 │  X-Mesh-Exit: node-us │                       │
  │                 │  X-Mesh-Hops: 4       │                       │
  │                 │                       │ mesh 前置步骤识别      │
  │                 │                       │ B≠出口, 路由: 下一跳直连 node-us
  │                 │                       │─CONNECT google.com:443▶│
  │                 │                       │  PA/Exit 同上, Hops:3  │
  │                 │                       │                       │ 出口==自己:
  │                 │                       │                       │ 剥 X-Mesh-*, PA
  │                 │                       │                       │ 按本机策略 direct
  │                 │                       │                       │─TLS──▶ google.com
  │◀───────────────────────── 响应/数据沿原连接返回 ──────────────────│
```

三类节点的处理：

**入口节点**（`Strategy::proxy` 分支识别 `mesh://`）：
1. **先剥再注入**：无条件 `del` 请求里客户端自带的全部 `X-Mesh-*` 头，防伪造透传（非 CONNECT 的 direct 请求会把未知头原样发给目标站）。
2. 确定出口：显式名查节点表（查无 → 502 `[[mesh: unknown node]]`）；`auto` 则对每个 exit 节点求路径代价取最小。
3. 路由计算：`MeshRoute::nexthop(exit)` 返回下一跳节点；无路可达 → 502 `[[mesh: no route]]`。
4. 组请求：dest 置为下一跳的真实地址（节点表 URL，userinfo 含 mesh 凭据），`chain_proxy = true`，注入 `X-Mesh-Exit: <出口名>`、`X-Mesh-Hops: <mesh-maxhops>`（计边数：maxhops=4 允许最多 4 条边、5 个节点的路径），交 `Host::distribute`。

**中继节点**（`distribute()` 的 mesh 前置步骤：请求含 `X-Mesh-Exit` 头且 Proxy-Authorization 解出 user=`mesh` 且校验通过）：
1. 出口 == 自己 → 按出口处理（**出口不检查 hops**——它到此为止，不再消耗跳数）。
2. `mesh-relay off` → 403 `[[mesh: relay disabled]]` 显式拒绝（不静默丢弃）。
3. `X-Mesh-Hops` 缺失、非数字或为 0 → 508 拒绝（防环兜底）。
4. 否则查路由得下一跳（须满足防环规则，见 4.3），`X-Mesh-Hops` 减一，`Proxy-Authorization` 重建（identifier 仍是最终出口名），转发。转发沿用 `Strategy::proxy` 的出口逻辑，`Via` 头照常追加。
4. 中继对 mesh 流量**不做 SNI 嗅探、不做 MITM**：`Guest2/Guest3` 在 `distribute()` 之前会对 CONNECT :443 做 SNI 嗅探（`should_sniff_sni`）并可能改写目标或 MITM，须为携带 mesh 凭据的请求加跳过条件——否则"中继透明"不成立，且嗅探会改写 `Dest.hostname` 破坏转发。中继不解析、不缓存请求体。

**出口节点**（`X-Mesh-Exit` == 本节点名）：
1. 剥掉 `X-Mesh-*` 头与 mesh 凭据。
2. 按本机策略处理该请求（通常 direct；出口节点自己的 sites.list 对进入的流量同样生效，如出口可以再定义"这些域名直连/阻断"）。**自环拒绝（硬规则）**：若本机策略把该目标再次送入 mesh（命中 `mesh://<其他节点>` 或 `mesh://auto` 选出了其他节点），直接 508 拒绝——出口语义是"离开 mesh"，出口策略再入 mesh 属于配置错误；若不拒绝，两台出口节点策略互指即可形成 hops 被反复重置的跨节点无界循环（见 4.3）。
3. 源地址保留（可选，新代码）：代理级联路径只追加 `Via`、不追加 `X-Forwarded-For`（例外：本机策略为 `forward` 时会注入出口视角的 XFF），`--rproxy-kp` 仅对 rproxy 路径生效，对 mesh 均不适用。若需要为 mesh 流量保留客户端源地址语义，出口需新增注入 XFF/源地址头的逻辑，不在此期实现。

UDP（CONNECT-UDP / h3 Datagram）与 WebSocket 在代理级联里语义不变，随 h2/h3 通路自然透传，mesh 不做特殊处理。

### 4.3 防环

三重机制，**只有第一道是无条件成立的**，另两道是收敛性优化与兜底：

1. **hop limit（硬保证）**：`X-Mesh-Hops` 每过一跳减一，减到 0 拒绝（508）。无论各节点视图如何分叉，任何环路都会在 ≤ `mesh-maxhops` 跳内被此规则截断。**唯一的例外是出口重入**：出口剥掉 `X-Mesh-*` 后若本机策略再把请求送进 mesh，hops 会重置、hop limit 失效——两台出口节点策略互指可形成无界循环（受 200 并发流上限自然限流但持续消耗）。此例外由出口的自环拒绝规则堵死（见 4.2 出口处理第 2 步）：出口发现目标再入 mesh 即 508。Via 检测帮不上忙——它只匹配本进程 pid，跨节点互指不会命中。
2. **距离严格递减（一致视图下的无环与质量保证）**：中继只把请求转发给"按本地链路状态库算出的、到出口最短路距离比自己小的节点"。全网视图一致时距离沿路径严格递减、不可能成环，且各跳独立决策的结果衔接成同一条最短路；视图分叉的窗口期（gossip 未收敛）里此规则不保证无环，由 hop limit 兜底，代价是个别请求多绕一跳或被拒。
3. **Via 检测（同节点回环兜底）**：现有 `check_header()` 的 `Via: HTTP/1.1 sproxy:<pid>` 检测，兜住"路由把下一跳选回自己"的本地配置错误。

**前置步骤插入点（实现约束）**：mesh 前置步骤必须位于 `distribute()` 中 `check_header()` 之后、`getBackend()` 之前。放在 `check_header` 之前会绕过 Via 检测；放在 `getBackend` 之后，mesh 凭据 identifier（出口节点名）会被 `getBackend` 当作 rproxy backend 名查表、落入 `distribute_rproxy` 报 404——mesh 与 rproxy 共用 identifier 命名空间，必须由 mesh 先拦截。

### 4.4 故障处理

- **peer 连接断开**：现有 `Proxy2::ping_check`（10s 周期 h2 PING，2s 无 ACK 判死）/ QUIC keepalive 负责检测；`MeshManager` 经 Proxy2 销毁回调感知后删边重算路由。**存量流量随连接一起断**（与任何代理级联一致，不做流级迁移）；新请求立即走新路由。
- **出口节点失联**：显式出口 → 502 报错；auto 出口 → 候选集合里去掉它，滞回窗口后切换。
- **中继失联**：入口的下一批请求重算路由绕开它；已在失联中继上的流量中断（同上）。
- **节点恢复**：peer 重连成功即重新入表、重新参与路由。
- 网络切换（换 Wi-Fi 等）：现有 `network_changed()` → `flushconnect()` + QUIC 连接迁移机制对 peer 连接同样生效。

## 5. 控制面设计

### 5.1 消息定义与落地

控制面消息是 peer 连接上的普通代理请求，**目标 authority 固定为 `localhost`**——每个节点的 `localhost` 都被 `reloadstrategy` 自动注册为 `local` 策略，请求因此进入 `File::getfile`（`res/file.cpp` 新增 `mesh/` 路径分支处理）。这是 rproxy 注册（`GET /rproxy/<name>` + `Host: localhost`）隐藏前提的显式化，不依赖专用 ALPN、不依赖节点名被对端注册为 local。

| 请求 | 方向 | 作用 |
| :--- | :--- | :--- |
| `GET http://localhost/mesh/hello` | 外连节点 → 对端 | 握手注册：携带本节点条目。对端校验签名后入表。 |
| `GET http://localhost/mesh/nodes` | 任意 peer | pull 对端当前完整节点表（响应 200 + JSON 条目数组）。 |
| `POST http://localhost/mesh/announce` | 任意 peer → 对端 | push 本节点最新条目（地址/能力变更时主动推）。 |
| `GET http://localhost/mesh/metrics` | 任意 peer | pull 对端上报的链路状态（它到各 peer 的 rtt/loss）。 |

**所有 `/mesh/*` 请求要求 mesh 凭据**（user=`mesh`），普通代理凭据与 localhost 免认证通道均不放行——防止普通本地用户拉取全网节点表。

节点表条目（JSON，字段名即线上格式）：

```json
{
  "name": "node-a.example.com",
  "addrs": ["https://node-a.example.com:443", "quic://node-a.example.com:443"],
  "caps": ["exit", "relay"],
  "via":  "node-c.example.com",
  "fp":   "sha256:base64(叶证书 DER 指纹)",
  "seen": 1727654000,
  "sig":  "base64(HMAC-SHA256(mesh_secret, 规范化串))"
}
```

- `via`：reach-via 字段。直连可达节点缺省；NAT 后节点填其锚定 peer 名，表示"经此节点可到达我"（见 5.4）。
- `addrs`：条目校验强制**每个 URL 的主机名必须等于节点名**（理由与威胁模型见 2.1——现有 TLS 钉扎的是拨号主机名，若允许 addrs 主机名 ≠ 节点名，投毒 addrs 即可劫持流量到攻击者自己的合法证书域名）。addrs 只声明同一域名的不同 scheme/端口。
- `fp`：叶证书指纹，供观测与未来逐节点密钥对升级时对账，首期不参与准入判断。
- `seen`：条目签名的 Unix 时间戳（秒）。接收校验**新鲜度窗口**：`|now - seen| ≤ 300s`——既拒旧条目回滚，也拒时钟超前的成员签出未来时间戳钉死条目；窗口外的条目不采纳、不传播，已有旧条目保留至 TTL 自然过期兜底。**节点时钟因此有硬依赖**（偏差 > 5 分钟的节点其自签条目会被全网静默拒收、自己却毫无感知），运维要求 NTP；`DumpMesh` 输出本节点条目在外网的采纳情况需要靠对端回报，Phase 2 起在 gossip 响应中捎带"我见到的你的 seen"供对账。
- `sig`：成员签名，防非成员投毒。**规范化串的精确定义**（HMAC 的输入字节）：

```
name + "\n" + join(addrs, "\n") + "\n" + join(caps, ",") + "\n" + via + "\n" + 十进制 seen
```

addrs 保持条目内声明顺序原样参与签名（顺序也是被签名内容的一部分）。

### 5.2 gossip 算法

push-pull 反熵，由周期 job（`AddJob` 自我重臂）驱动（`mesh-gossip-interval`，默认 30s）。**心跳轮转覆盖全部活跃 peer**，不做纯随机抽样：每周期按轮转顺序向 `⌈P/8⌉` 个 peer 发 `GET /mesh/nodes`（P 为活跃 peer 数），保证任意 peer 在 ≤ 240s 内至少被 touch 一次——这同时服务于三个目的：节点表交换、链路状态拉取（6.1 的 metrics 搭同一班心跳）、以及**重臂 peer 连接的 300s 空闲计时**（`Proxy2` 的 idle 只被"新请求"重置，h2 PING 不算；若靠随机抽样，32 peer 时约一半连接会被周期性回收再重连，形成持续 churn）：

1. 每周期按轮转发 `GET /mesh/nodes` 并捎带 `GET /mesh/metrics`，合并收到的条目（校验签名 + 新鲜度窗口 + 同名条目时间戳单调）；
2. 本节点条目变更（地址/能力变化）时立即 `POST /mesh/announce` 给所有活跃 peer；
3. 本节点条目每周期重新签名续期（更新 `seen`），随 pull/push 传播；
4. 条目 TTL 过期（默认 `10 × gossip-interval`）：源节点持续在网就持续续期，静默退网的节点最终从所有表里消失；
5. 同名条目检测到签名不同且 `seen` 交替上升时判定为命名冲突，本地告警（LOGE）并放弃其中后到者。

规模假设：节点数 ≤ 10² 量级，O(n²) 的全表交换没有压力；节点数再上一个量级时把全表 pull 改为带版本号增量同步（开放问题，见 12 节）。

### 5.3 peer 连接维护

- 启动时：对每个 `mesh-peer` 种子建 peer 连接；随后对节点表中**直连可达**（无 `via`）的节点逐个建连，受 `mesh-max-peers` 上限约束（默认 32）。超限淘汰规则：对"非当前路由必需且空闲最久"的连接**停止主动保活（不再轮转 touch），放任 300s idle 回收**——不主动 `deleteLater`，因为 `responsers` 池按 dest（不含凭据）合并连接，主动断开会连带杀掉同 dest 的普通上游在途流量。
- peer 连接 ALPN 强制 h2/h3：`MeshManager` 建连后校验协商结果，降级到 h1 即断开重试（h1 路径的 SNI 嗅探/MITM 行为与 mesh 语义冲突，见 4.2）。
- **保留现有 300s 空闲回收，不做豁免**：前提正是 5.2 的心跳轮转——任意活跃 peer 在 ≤ 240s 内必有一次控制面请求，idle 计时被持续重臂（注意 h2 PING 不重置 idle，只有新请求会）；超出 `mesh-max-peers` 管理范围、被停止保活的连接由 idle 回收清理。无需改动 `Proxy2/Proxy3` 的 idle 逻辑。
- 保活：`Proxy2` 的 h2 PING（10s 周期）+ 2s 判死，QUIC keepalive 同理，现成。
- 重连：per-peer 指数退避 1s→32s，30 分钟后重置（仿 `Rguest2` 模式，但退避状态独立于实例，不共享 static 变量）。

### 5.4 NAT 后节点

无公网地址的节点（如家里的盒子）：

- **作为入口**：正常。它主动与种子建立 peer 连接，`hello` 时声明 `via: <种子名>`；它的转发请求经 peer 连接（或再经中继）送达出口。**它不需要证书**（只发起 TLS，不接受入连）。
- **作为出口/被直连**：首期不支持。后续阶段复用 rproxy 的反向通道机制（`Rguest2` 的 h2 PUSH 注册模式）：NAT 节点把 peer 连接"注册"给对端，对端即可通过该既有连接反向把请求送达 NAT 节点，`via` 字段就是路由表里的中继边。这是 Phase 4 的内容。

## 6. 探测与路由算法

### 6.1 探测

探测搭载在既有连接上，不发独立探测包，但**采样调度必须是 mesh 自己的周期 job**：

| 来源 | 度量 | 说明 |
| :--- | :--- | :--- |
| mesh 应用层探测 `GET /mesh/ping` | RTT | MeshManager 经 peer 连接周期发 HTTP 探测请求、测响应往返。不用 `Proxy2::ping_check`（其 job 在 onRead 里重臂，读取间隔小于 10s 的连接 PING 永远不会发出，Android 构建下只随 SendData 触发）。应用层探测同时重臂连接的 300s 空闲计时，一石二鸟，也是 gossip 心跳的载体。 |
| `Proxy3` / QUIC | RTT、丢包 | 拥塞控制的 `smoothed_rtt` 随每次 ACK 持续更新（`quic_qos`），忙闲皆有样本，直接读取即可。 |
| TCP（h1 降级时） | RTT | `TCP_INFO`（现有代码仅在 dump 时读取，连续采样需新增读取逻辑）。peer 连接已强制 h2/h3（5.3），此项仅兜底。 |

- 采样周期 = `mesh-probe-interval`（默认 10s），EWMA 平滑（rtt: 系数 0.125；loss: 0.25），抑制抖动。
- 探测结果即本节点的链路状态，随 5.2 的心跳轮转对外发布（`/mesh/metrics`）。**边有 TTL = 600s**（≥ 2× 心跳覆盖周期 240s，从对端最近一次上报时间起算）：对端静默失联后它的边不会残留在全网视图里，也不会因分发节奏贴近而周期性掉边。
- 没有活跃连接的节点没有本地度量——路由图中就不存在那条直连边（本来也不该有）。

### 6.2 拓扑与路由计算

- 每个节点把收到的所有链路状态报告与本地探测合并成**全网图**：点 = 节点，边 = peer 连接（任一端上报即算存在，边权取两端上报的较大值——保守估计。注意 QUIC 的 loss 是发送方向统计，取 max 会系统性高估其中一侧，Phase 1 只有 RTT 无此问题，Phase 3 起接受该保守性）。
- 边权：`w(e) = rtt_ewma × (1 + α × loss)`，`α` 默认 10（1% 丢包按 10% 代价惩罚）。
- 路径代价：`W(P) = Σ w(eᵢ) × φⁱ`，`i` 为跳序（从 0 起），`φ` 默认 1.5——每多一跳，后续边的代价放大，抑制"两跳低延迟串联胜过一跳稍慢直连"这类抖动性占优。
- 出发点运行 Dijkstra 得到最短路树；**只用下一跳**，即用户确认的"直连或选个中继、中继再自己选"的逐跳语义。全网视图一致时，各跳独立决策的结果天然衔接成同一条最短路（见 4.3 对不一致窗口的讨论）。

### 6.3 切换滞回

逐跳决策不意味着路径抖动：

- 每个出口（含 auto 的当前选择）缓存最近路由结果，仅在**新路径代价 < 旧路径代价 × 0.8**（改善超过 20%）且**距上次切换 > 30s** 时才切换；
- 切换只影响新请求：旧连接不断，在途请求沿原路径走完；不再承载流量的旧中继连接由现有 300s 空闲回收自然清理（见 5.3）。

### 6.4 auto 出口求值

```
candidates = 节点表中 caps 含 exit 的节点
exit = argmin_{e ∈ candidates} W(path(本节点 → e))
```

本节点不计入候选（见 4.1）。候选为空（全网无其他 `exit` 节点或全部失联）→ 502 `[[mesh: no exit]]`。出口对目标站点的可达性盲区（路径最优 ≠ 目标可达）在 12 节列为开放问题，Phase 4 考虑用出口侧连接失败反馈修正评分。

## 7. 模块划分与代码集成点

### 7.1 新增模块

```
src/mesh/                          新目录，静态库（仿 hook_lib 挂入 CMake）
  mesh_manager.h/.cpp              单例：节点表、peer 连接生命周期、gossip/probe 周期 job、dump_stat
  mesh_gossip.h/.cpp               条目编解码、规范化串签名校验、push-pull 调度
  mesh_probe.h/.cpp                度量采集（读 Proxy2/Proxy3/SocketRWer 统计）、EWMA
  mesh_route.h/.cpp                拓扑图、Dijkstra、逐 hop 决策、防环规则、滞回缓存
  mesh_route_test.cpp              路由算法单元测试（图构造/最短路/防环）
```

CMake 改动：`src/CMakeLists.txt` 增加 `add_subdirectory(mesh)`，目标名加入 `SPROXY_CORE_TARGETS`；Linux 分支的 `--start-group` 链接列表与 Apple 分支的 `SPROXY_LIBS` 列表都要加。

### 7.2 既有代码改动点

| 文件 | 改动 |
| :--- | :--- |
| `src/res/responser.cpp` | ① `distribute()` 的 `Strategy::proxy` 分支：`parseDest` 前拦截 `mesh://` ext，调 `MeshManager` 入口处理；② `distribute()` 在 `check_header()` 之后、`getBackend()` 之前加 mesh 前置步骤：识别 `X-Mesh-Exit` + mesh 凭据，走中继/出口处理（位置是硬约束，理由见 4.3）。 |
| `src/res/file.cpp` | `File::getfile` 增加 `mesh/` 路径分支：控制面四个端点，强制 mesh 凭据校验（见 5.1）。 |
| `src/req/guest2.cpp`、`guest3.cpp`、`guest.cpp` | 携带 mesh 凭据的请求跳过 `should_sniff_sni` 嗅探与 MITM（见 4.2 中继处理；h1 的 `Guest` 在 distribute 之前同样嗅探，作为 peer 强制 h2/h3 之外的兜底）。 |
| `src/res/proxy2.cpp`（及 proxy3） | 销毁路径增加对 `MeshManager` 的断连通知（现在只有 `responsers.erase`），供删边重算路由（Phase 3 实现）。 |
| `src/misc/config.c` | `option_detail[]` 增加 mesh 系列条目（`mesh-relay`/`mesh-exit` 用 `option_enum` 承载 on/off，现有 bool 选项机制忽略参数值）；`postConfig()` 校验：mesh-secret 必设、长度上限、拒绝与 `--insecure` 并存、检测与普通用户名 `mesh` 冲突；peer URL 解析与"命中 proxy 策略即跳过"的递归防护在 `MeshManager::Start()` 做（解析失败直接退出，策略命中告警跳过）。 |
| `src/misc/config.h` | `struct options` 增加对应字段。 |
| `src/misc/strategy.cpp` | `addsecret` 装载 mesh 凭据（mesh-secret 单独选项、注入 secrets 校验链）。 |
| `src/prot/rpc.h`、`src/req/cli.cpp`、`src/client/client.cpp` | `SproxyServer`/`SproxyClient` 增加 `DumpMesh()`（节点表/度量/路由，文本输出，同 `DumpStatus` 风格）与 `MeshFlush()`（清空节点表重新发现）；scli 增加 `mesh` 子命令。 |
| `src/server/server.cpp` | `postConfig` 后检测 `mesh` 配置项，`MeshManager::instance().start()`。 |

### 7.3 可观测性

- `dump_stat`（SIGUSR1 / `/status`）：输出节点表、peer 连接状态、各边度量、各出口当前路由与代价。
- 每次转发决策打 `LOGD(MESH, ...)`：`mesh: <req> exit=<name> via=<下一跳> hops=<n> cost=<w>`。
- `tracker` 是进程内的（不跨跳序列化），全链路排查靠各跳独立 trace 日志按 `X-Mesh-Exit` 头与时间对齐；如需强关联可后续增加跨跳请求 ID 头（开放问题）。

## 8. 配置项

```
mesh <节点名>              # 启用 mesh。可直连节点须与证书域名一致；NAT 入口节点用组织前缀-名字（如 home-a.alice）
mesh-secret <密钥>         # 网络密钥（必设；凭据用户名固定为 mesh）
mesh-peer <url>            # 种子节点，可多条（https://node.example.com[:443]，或 quic://）
mesh-relay on|off          # 允许中继他人流量，默认 on（option_enum）
mesh-maxhops <n>           # 最大跳数，默认 4
mesh-max-peers <n>         # 最大直连 peer 数，默认 32
mesh-probe-interval <秒>   # 探测采样周期，默认 10
mesh-gossip-interval <秒>  # 节点表交换周期，默认 30（全网应配置一致且 ≤300，见 12-9）
mesh-exit on|off           # 允许做出口（auto 候选），默认 on
```

配置示例——三节点网（A 是 NAT 后入口，B、C 有公网域名）：

```bash
# 节点 B / C（各自机器上）
sproxy --bind=0.0.0.0:443:ssl --cert=node-b.example.com.crt --key=node-b.key \
       --mesh=node-b.example.com --mesh-secret=<网络密钥>

# 节点 A（NAT 后，仅入口）
sproxy --mesh=home-a.alice --mesh-secret=<网络密钥> \
       --mesh-peer=https://node-b.example.com:443 \
       --mesh-peer=https://node-c.example.com:443
```

A 的 sites.list：

```text
us          alias  mesh://node-b.example.com
google.com  proxy  @us
netflix.com proxy  mesh://auto
```

## 9. 分阶段实施计划

### Phase 1 — MVP：静态组网 + 直连转发

- `mesh://<节点名>` scheme、alias/策略集成、distribute 两处挂接（前置步骤含防环三件套的位置约束）；
- 节点表只来自 `mesh-peer` 静态配置（无 gossip）；
- 出口/入口处理（无中继：只有一跳直连到出口）、防环三件套与出口自环拒绝；
- 独立 h2 PING job RTT 探测（不依赖 `Proxy2::ping_check`，见 6.1）+ dump_stat/RPC 可见性；
- **验收**：两节点，A 上 `google.com proxy mesh://B` 通；`scli mesh` 可见节点与 RTT；出口失联时报错信息正确；带 `X-Mesh-*` 头但无 mesh 凭据的请求不进入 mesh 语义（入口剥头后按普通策略处理）。

### Phase 2 — gossip 发现 + auto 出口

- `/mesh/*` 控制面（file.cpp handler + localhost authority + mesh 凭据门禁）、条目签名/新鲜度窗口/TTL；
- 三节点以上自动同步节点表；
- `mesh://auto` 出口选择（仅按本节点直连度量）；
- **验收**：A 只配一个种子，能发现第三个节点；杀掉 auto 选中的出口，流量在滞回窗口后切换；普通代理用户访问 `/mesh/nodes` 被拒；同名冲突条目触发告警。

### Phase 3 — 链路状态 + 逐跳中继路由

- `/mesh/metrics` 链路状态交换（含边 TTL）、全网拓扑、Dijkstra、逐跳转发、防环三件套；
- NAT 入口节点（via）经中继触达出口；
- **验收**：四节点哑铃拓扑（A—B … C—D 两簇，仅 B—C 互通），A 到 D 的请求经 B、C 中继成功；`X-Mesh-Hops` 注入为 0 的伪造请求被拒；中继节点宕机后自动重路由；mesh 流量在中继上不被 SNI 嗅探/MITM。

### Phase 4 — 体验与硬化

- QUIC peer 优先/连接迁移在选路中的应用；利用 peer 连接的 observed address 做轻量打洞增强（复用 QUIC PATH_CHALLENGE）；
- NAT 节点作为出口（rproxy PUSH 反向通道复用）；
- webui 节点管理页、metrics 输出、出口失败反馈修正 auto 评分、跨跳请求关联头；
- 逐节点密钥对签名（升级信任模型的可选路径）。

## 10. 测试计划

- **单元测试**（`src/mesh/mesh_route_test.cpp`，随 `cd build && make` 构建）：
  - 拓扑图构建与合并（两侧上报、边权取大、边 TTL 过期）；
  - Dijkstra 正确性：直连 vs 一跳中继 vs 两跳的代价比较（验证 φ 惩罚）；
  - 防环：一致视图下距离递减无环；构造视图分叉场景验证 hop limit 截断；
  - 条目规范化串签名、时间戳新鲜度窗口、同名冲突检测。
- **集成测试**（在 `test/test.sh` 中新增 mesh 多实例编排用例，复用其现有多实例脚本模式与 `test/docker` 环境）：
  - 两节点直连转发（Phase 1 冒烟）；
  - 三节点 gossip 收敛（断言各节点 dump 的节点表一致）；
  - 哑铃拓扑中继转发与中继宕机重路由；
  - auto 出口故障切换；auto 候选为空时报 `[[mesh: no exit]]`；
  - 出口自环拒绝：出口本机策略把目标再指回 mesh 时 508；
  - 越权测试：无 mesh 凭据的 `X-Mesh-*` 伪造请求按普通策略处理（若伪造者另带 identifier，按现有 rproxy 语义 404，总之不进 mesh）；普通凭据访问 `/mesh/nodes` 被拒；`X-Mesh-Hops` 缺失/非数字视为 0 拒绝。

## 11. 安全考量

- **成员投毒（DoS，非劫持）**：任意持密钥成员可伪造他人条目（HMAC 是成员级认证，非节点级），例如把 `node-x` 的条目投毒成失效地址。缓解：条目时间戳单调 + 新鲜度窗口 + **addrs 主机名强制等于节点名**（5.1）——后者是关键：TLS 钉扎的是拨号主机名，强制 addrs 与节点名同域后，投毒的 addrs 只能指向节点名自己的域名，攻击者无法把流量引到自己的合法证书域名上，投毒退化为纯 DoS（连不上），不构成 MITM。彻底解决靠 Phase 4 的逐节点签名。
- **明文 http 地址**：节点若有明文 `http://` 监听，会被发布进 own_entry 的 addrs；经该地址的 peer 拨号使 Basic 凭据明文暴露（与现有明文上游代理同威胁模型）。生产部署应只以 `https://`/`quic://` 监听承载 mesh。
- **配置级环路（出口互指）**：两台出口节点的策略互相把对方当 mesh 出口，若无拦截会形成 hops 被反复重置的无界循环。已由出口自环拒绝规则堵死（4.2 出口处理第 2 步），并在测试计划中有专项用例。
- **命名冲突**：NAT 节点名无全局注册保障，两个同名节点会让条目按 `seen` 交替震荡。缓解：命名约定 + gossip 侧冲突检测告警（5.2 第 5 条）。
- **密钥泄漏**：mesh secret 泄漏即全网开放。轮换方案（多密钥并存灰度切换）为开放问题；短期手段是更换密钥并重启全网。
- **资源滥用**：中继/出口是义务，mesh 凭据与普通代理凭据分离已是第一道闸；后续可加 per-peer 限流（现有 `killCon`/统计基础上）。
- **环回放大**：hop limit 上限（`mesh-maxhops` 默认 4）限制了任何环路的最大放大倍数；出口重入是唯一例外，由自环拒绝堵死（见上条）；Via 检测兜底同节点回环。

## 12. 风险与开放问题

| # | 问题 | 现状/倾向 |
| :--- | :--- | :--- |
| 1 | 拓扑不一致窗口期的路径震荡 | hop limit 无条件截断 + 滞回压危害，不做分布式一致性协议；递减规则只承诺一致视图下的质量。 |
| 2 | mesh secret 轮换 | 开放。倾向多密钥并存（新旧同时有效 N 小时）。 |
| 3 | 对称 NAT 双侧都在 NAT 后 | 只能靠中继（有公网侧的 peer），打洞增强仅对锥形 NAT 有效，文档明确不承诺。 |
| 4 | auto 出口对目标可达性盲区 | 路径最优 ≠ 目标可达。Phase 4 用出口侧连接失败率反馈修正评分。 |
| 5 | 大规模节点表（>10²） | 全表 pull 改增量同步（版本号/时间戳水位），协议已留扩展位。 |
| 6 | 出口节点策略二次介入 | 出口的本机策略会作用于进入的流量（设计如此，文档已注明）；若造成困惑可加 `mesh-trust-all`（进入流量视为已授权直连）。 |
| 7 | QUIC 单向 loss 度量 | 边权取两端 max 是保守估计，接受系统性高估；如需精确可改双向均值（Phase 4 评估）。 |
| 8 | 跨跳请求关联 | tracker 不跨进程，现状靠日志按头对齐；需要时加跨跳请求 ID 头。 |
| 9 | 节点时钟依赖 | 新鲜度窗口 ±300s 是硬依赖，NTP 是运维前提；超差节点的条目被全网静默拒收（5.1 已含对账机制）。另：全网 mesh-gossip-interval 应一致且 ≤300s，否则发送方较慢的自签条目会被默认配置的接收方拒收。 |
| 10 | addrs 与节点名强绑定的代价 | 节点换域名需全网重新签名条目；RWer 独立 verify-name 覆盖（pin 节点名、拨号任意 addrs）是 Phase 4 的解除方案。 |
