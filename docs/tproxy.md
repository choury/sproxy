# tproxy 透明代理

`tproxy` 将 TCP / UDP 连接透明地劫持到本地 `sproxy`，自动复用代理策略与 MITM/FakeIP 机制，对客户端完全无感知。该功能仅在 Linux 上支持（作为 `--tproxy` 监听）。该方式实现的透明代理较VPN方式更加灵活和轻量，如果只希望代理本机tcp/udp流量，推荐使用`tproxy`方案。

## 工作原理

- **监听与原始目的地址获取**：`--tproxy <bind>` 会在指定地址/端口同时开启 TCP、UDP 监听。默认打开 `IP[V6]_TRANSPARENT`，或在启用 `--bpf` 时通过 eBPF 记录并模拟 `SO_ORIGINAL_DST` 返回值。
- **TCP 流**：接入连接后通过 `SO_ORIGINAL_DST`/`getsockname` 取得真正目的地址，构造内部 `CONNECT <dst>` 请求交给通用转发管线处理。启用 eBPF 时会把发起进程的 `comm/pid` 追加到 User-Agent，便于追踪来源。
- **UDP 流**：首个数据包到达时，新建一个绑定原始目的地址的 UDP 套接字并连接到客户端，后续报文共享同一 `Guest_tproxy` 会话。若目标端口为 53，会直接走内置 `FDns`，可配合 `--disable-fakeip` 决定是否返回真实地址。
- **路由与回包**：对于需要通过 tproxy 捕获的流量，需将包能劫持到tproxy端口；可以用策略路由（fwmark + local table）或 eBPF 标记来完成。

## 启用方式

### 1）iptables TPROXY（传统方案）

在内核支持 TPROXY 的场景下使用，需 root 权限以设置 `IP[V6]_TRANSPARENT` 与策略路由。

1. 启动 sproxy：

   ```bash
   ./sproxy --tproxy [::]:3333 ...
   ```

2. 配置内核转发与策略路由（IPv4 示例，端口/mark 与上面的命令保持一致）：

   ```bash
   iptables -t mangle -A PREROUTING -m addrtype --dst-type LOCAL -j RETURN
   iptables -t mangle -A PREROUTING -p udp -j TPROXY --on-port 3333 --tproxy-mark 3333/3333
   iptables -t mangle -A PREROUTING -p tcp -j TPROXY --on-port 3333 --tproxy-mark 3333/3333
   ip rule add fwmark 3333 lookup 3333
   ip route add local 0.0.0.0/0 dev lo table 3333
   ```

   - IPv6 可使用 `ip6tables`/`ip -6 rule`/`ip -6 route` 写法。
   - 若仅拦截指定网卡或网段，可在 PREROUTING 规则中追加 `-i <ifname>` 或 CIDR 匹配。

### 2）eBPF cgroup 重定向（无需 iptables）

适用于 cgroup v2 场景，通过 sockops 程序将 cgroup 内进程的 `connect`/`sendmsg` 重定向到 `--tproxy` 端口，并在 `SO_ORIGINAL_DST` 时返回记录的原始目的地址。避免了 TPROXY 依赖，但不适用于容器环境。

1. 准备 cgroup 并把要劫持的进程放入其中

   ```bash
   mkdir -p /sys/fs/cgroup/sproxy
   echo $$ | sudo tee /sys/fs/cgroup/sproxy/cgroup.procs
   ```

2. 启动 sproxy：

   ```bash
   ./sproxy --tproxy 3333 --bpf=/sys/fs/cgroup/sproxy
   ```

   - `--bpf` 负责加载/卸载 BPF 程序并告知监听的本地地址；重定向仅作用于该 cgroup。

## 排查要点

- 日志中出现 “failed to get dst addr for tproxy” 多为 `SO_ORIGINAL_DST` 不可用，检查是否缺少 TPROXY/BPF 重定向或进程未进入 cgroup。
- 需要 root 权限（设置透明套接字、加载 BPF、写策略路由）。
- UDP 解析走内置 FDns，命中 DNS FakeIP 时返回本机地址；若希望直连真实 IP，启动时添加 `--disable-fakeip`。
