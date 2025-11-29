# VPN 模式

基于 TUN 设备接管本机的 TCP / UDP / ICMP 流量，将其送入 `sproxy` 的通用转发、策略和 MITM/FakeIP 管线。仅 Linux / Android 支持，创建 TUN 需要 root 权限（`--tun-fd` 由外部创建则不需）。

## 工作方式与地址规划
- TUN 地址：IPv4 `198.18.0.1/15`，IPv6 `64:ff9b::c612:1/111`，MTU 默认 16384，开启 virtio offload 减少拷贝。
- DNS：TUN 上的 UDP/53 会交给内置 `FDns`，非 `direct` 策略的域名默认返回 FakeIP（198.18.0.0/15、NAT64 前缀 `64:ff9b::/111`），`direct` 且 `--disable-fakeip` 时返回真实 IP（可以绕过转发）。
- 协议：80/443 端口自动走 HTTP/HTTPS/HTTP3 处理（含 MITM 与 SNI 转发），其他 TCP/UDP/ICMP 会被转换成内部 `CONNECT` 请求并复用策略系统。

## 启动与路由
### 1）在本机创建 TUN（常见用法）
```bash
sudo ./sproxy --tun --interface eth0 --set-dns-route
```
- 全局代理：把默认路由/需要代理的前缀指向 TUN；若修改了默认路由，可选择：`--interface=<uplink>` 绑定出口网卡，或 `--fwmark` 配合策略路由，避免回环。
- `--set-dns-route` 推荐与 FakeIP 一起使用，返回的FakeIP 连接时默认会走 TUN，这种用法适用于只通过域名的流量代理。
- 可选：`--pcap=/tmp/vpn.pcap --pcap-len=256` 抓包；`debug enable vpn` 打开调试日志。

### 2）复用已有 TUN FD（Android / 外部守护进程）
使用 `--tun-fd <fd>` 直接接管已打开的 TUN 描述符（例如 Android VpnService 传入、或由外部脚本预创建）。此模式下接口地址、路由和 DNS 需由外部配置为与上面一致，`sproxy` 仅负责读写该 FD。

## 策略与行为
- 与普通代理一致，`sites.list` 中命中 `direct` 会用真实 DNS 直连，其余按策略走上游或 MITM。
- `--disable-fakeip` 关闭 FakeIP，全部 DNS 返回真实地址（不再依赖 198.18.0.0/15 捕获），适合仅想利用 TUN 做“全局直连 + 少量代理”场景。
- HTTP UA 可用 `--ua` 自定义，默认会附带发起进程信息/SEQ，便于排查。

## 协议栈实现
- **用户态 TCP/IP 栈**：支持 IPv4/IPv6，TCP/UDP/ICMP/ICMPv6（echo、unreach、ptb 等），完成握手、重传、SACK、窗口扩展、时间戳、保活；TCP 维护序列/ACK/RTO/MSS 协商，UDP/ICMP 为轻量状态机。
- **非包粒度转发**：TUN 报文被重建为新的 TCP/UDP 连接，通过 HTTP `CONNECT`，不会把原始 TCP 包再封进隧道，避免双层重传/队头阻塞。
- **语义重建的取舍**：新的连接会重新选择窗口、拥塞控制与 MSS，丢失原 DSCP/TTL/自定义 TCP 选项等细节；不适合需要保真原包或精确链路测量的场景。
- **域名感知与代理融合**：内置 FakeIP/NAT64、FDns 注入、Quic/H3 专用分支，所有会话走策略、MITM、SNI、上游切换——更像“透明代理管线”，而非远端 NAT/桥接。
- **无 L2 功能**：不支持 ARP/DHCP/广播/组播，也不承载 mDNS/NetBIOS 等局域网发现；适合出口代理与分流，不用于组建局域网。

## 排查要点
- `dump status`/`dump usage` 查看活跃会话；`debug enable vpn` 输出 TUN 报文方向与标志。
- 确认路由：`ip route show | grep 198.18.0.0/15`；若上游连接绕回 TUN，检查 `--interface`/`--fwmark` 配置。
- `--set-dns-route` 或者修改默认路由确保默认报文经过VPN接口；用 `dig example.com` 验证是否收到 FakeIP（198.18.0.0/15 或 NAT64 前缀）。
