# Hook 框架使用指南

本文介绍如何通过 sproxy 内置的 Hook 框架，在运行时把自定义逻辑注入到特定代码位置（Hook 点）。支持两种回调方式：

- **共享库回调（`.so`）**：通过 `dlopen` 加载，回调代码与 sproxy 运行在同一进程空间，可以直接访问参数引用。
- **BPF 沙箱回调（`.elf`）**：通过内嵌的 bpfvm 虚拟机执行，回调代码运行在隔离的沙箱中，通过 KV 序列化机制与 sproxy 交互。

## 基本概念

- **Hook 点**：由 `HOOK_FUNC(...)` 宏声明，作为插桩位置。宏内部生成一个带 `__hook_registed` 后缀的静态变量，用于标识是否已经注册。宏通过 `#__VA_ARGS__` 自动提取参数名，供 BPF 回调使用。
- **HookManager**：Hook 框架的核心单例，负责收集 Hook 点、加载回调并分发调用。

## Hook 点发现流程

为了确保 Hook 点始终可见，框架提供静态发现和动态注册两条路径，两者互为补充。

### 静态发现（启动期）

- **触发时机**：`sproxy` 启动期间，当 `HookManager` 构造完成。
- **前置条件**：编译时启用了 `libelf`（`HAVE_ELF`）。
- **执行方式**： `HookManager` 解析 `/proc/self/exe`，查找所有名称以 `__hook_registed` 结尾的 ELF 符号，并将其加入 Hook 列表。
- **优点**：即便某段代码尚未运行，对应的 Hook 点也能被 `dump hookers` 命令立即列出，方便提前布置回调。

### 动态注册（运行期兜底）

- **触发时机**：代码首次执行到某个 `HOOK_FUNC(...)` 宏时。
- **实现机制**：宏体内的静态布尔值初始为 `false`。第一次命中时，会调用 `HookManager::AddHooker` 注册 Hook 信息（函数名、位置、地址等），随后将布尔值置为 `true`，避免重复注册。
- **适用场景**：在不支持 `libelf` 的平台（例如 macOS）或禁用了静态扫描的部署环境中，只要代码被执行过一次，Hook 点就能被捕获。

## CLI 操作

`scli` 是与 Hook 框架交互的主要工具，以下示例基于默认的 UNIX socket 部署。

1. **连接服务**
   ```bash
   # sproxy 通常在 /var/run/sproxy.sock 或 /tmp/sproxy.sock 暴露 UNIX socket
   scli -s /var/run/sproxy.sock
   ```

2. **查看 Hook 点**
   ```text
   > dump hookers
   Hookers:
     0x5555558f1a00: Test::operator()(int, double):20
     0x5555558f1a04: void test_func(std::string):28
   Callbacks:
   (empty)
   ```
   - `Hookers` 部分展示已发现的 Hook 点地址和源码位置。
   - `Callbacks` 列出当前已加载的回调及其挂接位置。

3. **挂接回调**
   - 共享库：`hooker enable <hook_address> <path>.so`
   - BPF 程序：`hooker enable <hook_address> <path>.elf`
   - 框架根据文件扩展名自动选择加载方式。
   ```text
   > hooker enable 0x5555558f1a00 /opt/hooks/my_callback.so
   > hooker enable 0x5555558f1a00 /opt/hooks/my_filter.elf
   ```

4. **取消挂接**
   - 命令格式：`hooker disable <hook_address>`
   ```text
   > hooker disable 0x5555558f1a00
   ```

## 编写共享库插件（.so）

Hook 插件本质上是一个导出固定入口函数的 C/C++ 共享库。

1. **示例代码**（`my_callback.cpp`）
   ```cpp
   #include <iostream>
   #include <string>
   #include <tuple>

   template <typename... Args>
   auto get_args(void* args) -> std::tuple<Args&...> {
       return *static_cast<std::tuple<Args&...>*>(args);
   }

   extern "C" void hook_callback(void* args) {
       auto& [data, metadata] = get_args<int, const std::string>(args);
       std::cout << "Hook triggered, metadata: " << metadata << std::endl;
       data = 999; // 可以修改引用参数
   }
   ```
   - `hook_callback` 必须使用 `extern "C"` 暴露。
   - 模板参数顺序必须与 `HOOK_FUNC(...)` 中传入的参数完全一致。

2. **编译共享库**
   ```bash
   g++ -std=c++17 -shared -fPIC -o my_callback.so my_callback.cpp
   ```

## 编写 BPF 沙箱插件（.elf）

BPF 插件运行在 bpfvm 虚拟机中，通过 protobuf wire format 序列化的 KV 数据与 sproxy 交互。`HOOK_BPF` 宏自动从参数列表提取参数名，BPF 程序通过这些名字读写参数。

### 数据流

```
HOOK_BPF(hostname, port, protocol)
       │
       ▼
  BpfCallback::OnCall
       │
       ├─ 1. 序列化参数到 KV（protobuf wire format）
       │     key: "hostname" → value: "example.com"
       │     key: "port"     → value: 443
       │
       ├─ 2. 映射到 VM 内存，调用 entry(pb_ptr, pb_len)
       │
       ├─ 3. BPF 程序通过 bpf.h 中的辅助函数读取 KV
       │     通过 kv_set syscall 写回修改
       │
       └─ 4. 反序列化 KV → 回写到原始参数
```

### 示例代码（`my_filter.c`）

```c
#include "include/bpf.h"

/* 调用 kv_set syscall 写回 KV
 * type: 1=INT64, 2=UINT64, 3=STRING, 4=BYTES */
static void kv_set_int(const char* key, int64_t val) {
    bpf_kv_set(key, strlen(key), &val, sizeof(val), 1);
}

int hook_callback(uint64_t pb_ptr, uint64_t pb_len) {
    const void* pb = (const void*)pb_ptr;

    /* 读取参数 */
    int64_t port = pb_kv_get_i64(pb, pb_len, "port");

    /* 修改参数：将 HTTP 重定向到 HTTPS */
    if (port == 80) {
        kv_set_int("port", 443);
    }

    return 0; /* 0 = allow */
}
```

### 可用的 BPF 辅助函数

**读取 KV（从 protobuf 解码，头文件 `include/bpf.h`）：**
- `int64_t pb_kv_get_i64(pb, len, key)` — 读取有符号整数
- `uint64_t pb_kv_get_u64(pb, len, key)` — 读取无符号整数
- `const char* pb_kv_get_str(pb, len, key, &out_len)` — 读取字符串

**写回 KV（通过 syscall，定义在 `include/bpf_call.h`）：**
- `bpf_kv_set(key_ptr, key_len, val_ptr, val_len, type)` — 内联 syscall 封装
  - type: 1=INT64, 2=UINT64, 3=STRING, 4=BYTES

**日志：**
- `bpf_log(level, msg_ptr, msg_len)` — 输出日志到 sproxy 日志系统

### 编译 BPF 程序

```bash
# 编译为 BPF 目标文件（clang >= 18 用 -mcpu=v4，否则用 -mcpu=v3）
clang -target bpf -mcpu=v4 -O1 -std=c11 -nostdinc -fno-builtin \
    -c -o my_filter.o my_filter.c

# 链接为 ELF（-e 指定入口函数名）
bpf-ld -e hook_callback -o my_filter.elf my_filter.o
```

### 参数类型映射

| C++ 参数类型 | KV 类型 | BPF 读取函数 |
|---|---|---|
| `int`, `long` 等有符号整数 | INT64 | `pb_kv_get_i64` |
| `unsigned int`, `size_t` 等无符号整数 | UINT64 | `pb_kv_get_u64` |
| `std::string` | STRING | `pb_kv_get_str` |
| 指针类型 | UINT64（地址值，只读） | `pb_kv_get_u64` |

## 调试小贴士

- 使用 `dump hookers` 验证 Hook 点是否已经被发现。
- `Callbacks` 区块为空时，说明尚未加载任何回调，或加载失败。
- 共享库插件的日志可直接输出到 `sproxy` 的标准输出/日志系统。
- BPF 插件可通过 `BPF_CALL_LOG` syscall 输出日志到 sproxy 日志系统。
