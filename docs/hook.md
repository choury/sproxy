# Hook 框架使用指南

本文介绍如何通过 sproxy 内置的 Hook 框架，在运行时把自定义逻辑注入到特定代码位置（Hook 点）。通过 CLI 命令动态加载共享库（`.so`），可以在不中断服务的情况下实现调试、监控或快速试验新功能。

## 基本概念

- **Hook 点**：由 `HOOK_FUNC(...)` 宏声明，作为插桩位置。宏内部生成一个带 `__hook_registed` 后缀的静态变量，用于标识是否已经注册。
- **HookManager**：Hook 框架的核心单例，负责收集 Hook 点、加载回调库并分发调用。

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
   - `Callbacks` 列出当前已加载的共享库及其挂接位置。

3. **挂接回调**
   - 命令格式：`hooker enable <hook_address> <shared_library_path>`
   - 注意：共享库必须已存在于服务器可访问的文件系统中，`scli` 仅下发加载命令。
   ```text
   > hooker enable 0x5555558f1a00 /opt/hooks/my_callback.so
   ```

4. **取消挂接**
   - 命令格式：`hooker disable <hook_address>`
   ```text
   > hooker disable 0x5555558f1a00
   ```

## 编写 Hook 插件

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

## 调试小贴士

- 使用 `dump hookers` 验证 Hook 点是否已经被发现。
- `Callbacks` 区块为空时，说明尚未加载任何共享库，或共享库加载失败。
- Hook 插件的日志可直接输出到 `sproxy` 的标准输出/日志系统，便于快速排查。
