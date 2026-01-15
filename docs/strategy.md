# sproxy 路由策略机制

本文档详细阐述了 sproxy 项目的路由策略机制，包括核心概念、配置格式、匹配逻辑以及代码实现细节。

## 1. 概述 (Overview)

sproxy 的路由系统负责根据请求的目标主机（域名或 IP）及路径，决定如何处理该连接。核心决策包括：
- **直连 (Direct)**: 不经过代理，直接连接目标。
- **代理 (Proxy)**: 通过上游代理服务器转发请求。
- **拦截/本地 (Local/Block)**: 拦截请求、返回本地内容或直接阻断。
- **转发/重写 (Forward/Rewrite)**: 修改请求目标或转发到特定服务。

路由策略基于 **Trie (字典树)** 数据结构实现，支持高效的域名后缀匹配和 IP CIDR 前缀匹配。

## 2. 配置文件 (Configuration File)

sproxy 启动时会加载路由策略文件，默认路径如下：
1. `/etc/sproxy/sites.list`
2. `<PREFIX>/etc/sproxy/sites.list` (安装前缀路径下)
3. 当前运行目录下的 `sites.list`

你可以通过启动参数 `-P` 或 `--policy-file` 指定自定义的策略文件：
```bash
sproxy --policy-file /path/to/your/sites.list
```

## 3. 策略类型 (Strategy Types)

在配置文件中，每行定义一条规则，格式为：`[Host/IP] [Strategy] [Extension]`。

| 策略名称 | 关键字 | 扩展参数 (Extension) | 描述 |
| :--- | :--- | :--- | :--- |
| **Direct** | `direct` | 无 | 直接连接目标服务器，不经过代理。 |
| **Proxy** | `proxy` | 上游代理 URL | 将流量转发给上游代理。如 `https://user:pass@proxy.com:443` 或 `socks5://127.0.0.1:1080`。如果 Extension 为空，则使用全局默认代理服务器。 |
| **Block** | `block` | 正则表达式 | 阻断连接。如果提供了正则参数，则仅阻断匹配该正则的路径（仅限 HTTP或MITM时）。 |
| **Local** | `local` | 无 | 标识为访问 sproxy 内置的 Web 服务（如 Web UI、PAC 文件）。 |
| **Forward** | `forward` | 目标地址 | 端口转发模式。将流量转发原样到 Extension 指定的目标 |
| **Rewrite** | `rewrite` | 目标地址 | 目标重写模式。将流量转发到 Extension 指定的目标，并同步修改 HTTP `Host` 头部为目标地址。 |

## 4. 配置示例 (Configuration Examples)

### 4.1 IP 规则 (CIDR 支持)
```text
# 私有网段直连
10.0.0.0/8 direct
192.168.0.0/16 direct

# 阻断特定 IP
8.8.8.8 block
```

### 4.2 域名规则
```text
# 精确匹配域名
google.com proxy

# 通配符匹配所有子域名 (不包含域名本身)
*.google.com proxy

# 直连特定域名
example.com direct
```

### 4.3 路径拦截 (HTTP Block)
```text
# 阻断 chat.openai.com 下匹配特定正则的 API 请求
chat.openai.com block /backend-api/moderations.*
```

### 4.4 转发与重写
```text
# 将 test.com 的请求转发到本地 8080 端口，Host 头部保持 test.com
test.com forward http://127.0.0.1:8080

# 将 google.com 重写并转发到特定反代服务器，Host 头部变为 my-proxy.com
google.com rewrite https://my-proxy.com
```

### 4.5 别名定义
支持一种伪策略类型 `alias`，用于定义别名。

#### 语法
`name alias value`

#### 示例
```text
# 定义别名
us     alias  socks5://user:pass@192.168.1.100:8080
jp     alias  https://user:pass@jp-server:443
internal alias http://10.0.0.1:80

# 引用别名 (Proxy)
google.com   proxy   @us

# 引用别名 (Rewrite)
# 相当于 rewrite http://10.0.0.1:80
test.local   rewrite @internal
```

## 5. 匹配机制 (Matching Logic)

### 5.1 域名匹配
域名使用 **后缀 Trie 树** 存储。匹配时按域名层级倒序查找（从顶级域名开始）。
- `*.example.com` 匹配 `www.example.com`、`api.test.example.com` 等。
- **注意**: 通配符规则 `*.example.com` 不包含 `example.com` 自身。

### 5.2 IP 匹配
IP 地址使用 **Bit Trie (二叉字典树)** 存储，遵循 **最长前缀匹配 (LPM)** 原则。

### 5.3 匹配优先级
1. **IP 优先**: 如果请求目标是 IP 地址，优先查 IP 规则表。
2. **域名匹配**: 如果是域名，查域名 Trie 表。
3. **路径匹配 (Block)**: 在域名匹配成功后，如果策略是 `block` 且配置了正则，会进一步检查 HTTP 请求路径。

## 6. 动态更新策略

sproxy 支持在不重启服务的情况下动态修改路由策略。

### 6.1 使用 scli 工具
`scli` 是 sproxy 自带的命令行客户端，支持动态添加、删除和查询策略。详细用法请参考 [cli.md](cli.md)。

### 6.2 自动持久化
通过 `scli` 或 Web UI 动态添加的非系统默认策略，会自动写回到 `sites.list` 文件中（如果文件可写）。

## 7. 特殊机制

### 7.1 Fake IP
sproxy 内部会将 `fake_ip` 默认标记为 `block`。这是为了处理 VPN/TUN 模式下，当 DNS 响应被截获并分配 Fake IP 时，防止这些 IP 的流量绕过策略控制。

### 7.2 本地策略限制 (restrict-local)
启动参数 `--restrict-local` 用于微调 `local` 策略：
- **关闭 (默认)**: 匹配到 `local` 的所有端口请求都会进入 sproxy 内置 Web 服务。
- **开启**: 仅当请求目标端口与 sproxy 监听端口一致时才视为 `local`，否则降级为 `direct`。这允许在同一台机器上运行 sproxy 和其他 Web 服务。
