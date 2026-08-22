# Reqable Windows x64 Reverse Engineering

> 针对 **Reqable Windows x64** 的 Flutter / Dart AOT 逆向练习项目。  
> 实现了在不建立账号登录会话的情况下，让客户端进入原本受订阅权限控制的功能分支。

## 项目简介

Reqable Windows 客户端基于 Flutter 构建，主要业务逻辑以 Dart AOT 形式运行。

本项目从 Reqable 的实际逆向出发，研究并定位客户端侧的登录 / 订阅权限判断路径，并使用 Runtime Patch 验证分析结果。

当前研究主要涉及：

- Reqable 登录 / 订阅权限相关逻辑定位
- Flutter AOT 匿名执行区域定位
- Runtime Pattern Scan
- Runtime Patch
- Dart AOT 中的 R15 / PP 分析
- Dart Object Pool Dump
- Tagged Object / Smi / String 基础识别

`tools/DartPPDumper.lua` 是逆向 Reqable 过程中编写的辅助分析工具。

---

## 实现方式

项目使用 `version.dll` Proxy 进入 Reqable 进程，在运行时监控 Flutter AOT Code Region，并对目标区域执行 Pattern Scan。

```text
Reqable.exe
    │
    ▼
version.dll Proxy
    │
    ├── 加载并转发系统 version.dll
    │
    ▼
启动工作线程
    │
    ▼
监控 Flutter AOT Region
    │
    ▼
Pattern Scan
    │
    ▼
定位目标逻辑
    │
    ▼
Runtime Patch
```

---

## 为什么需要监控 AOT Region

Reqable 的 Dart AOT 执行区域并不适合只按传统 PE `.text` Section 处理。

实际运行中可以观察到较大的匿名可执行内存区域，并且在创建新的 Reqable 窗口后，还会出现新的 AOT Code Region。

因此项目不会只在启动时扫描一次，而是持续监控新的候选 Region：

```text
新 AOT Region
    ↓
Pattern Scan
    ↓
匹配目标代码
    ↓
再次处理
```

当前主要关注：

- `MEM_COMMIT`
- `MEM_PRIVATE`
- 较大的 Region
- Allocation 阶段具有写权限
- 当前具有执行权限

这也是 `MemMonitor` 存在的主要原因。

---

## Flutter / Dart AOT 逆向中的问题

Flutter Android / iOS 的公开逆向资料已经比较多，但 **Flutter Windows x64** 的研究资料和工具几乎没有，这也是本项目的研究重点。

Reqable 使用 Flutter / Dart AOT 后，传统 Windows x64 逆向的一些常用途径会明显失效。

### IDA 函数识别不完整

IDA 漏掉大量实际正在执行的 Dart AOT 代码。

因此：

- Functions Window 不一定完整
- Call Graph / Xref 可能缺失
- 某些真实函数可能仍显示为 undefined bytes
- Hex-Rays 自动恢复出的函数边界和参数不能完全相信

### 字符串 Xref 不存在

Dart AOT 中大量对象通过 Object Pool 间接访问。

汇编中经常出现：

```asm
mov rax, [r15+0x1234]
```

实际关系可能是：

```text
AOT Code
   ↓
[r15 + offset]
   ↓
Object Pool
   ↓
Tagged Dart Object
   ↓
String / Object
```

因此即使 IDA 能看到字符串，也没有直接 Xref。

### R14 / R15 具有 Dart Runtime 语义

在 Dart AOT x64 中，经常可以看到：

```asm
[r14+xxx]
[r15+xxx]
```

这些寄存器不能简单按普通 C/C++ 参数或结构体指针理解。

逆向 Reqable 时，恢复 R15 / PP 和 Object Pool 对定位业务对象非常重要。

### 调用栈和静态分析都只能作为辅助

Flutter Framework、Dart Runtime 和 Reqable 自身业务代码混在同一套 AOT 代码中。

再加上：

- Framework 高频调用带来的大量噪音
- Dart Tagged Object
- Release AOT 优化
- 函数内联
- SDK / Engine 版本变化

单纯依赖 IDA F5、字符串 Xref 或 x64dbg Call Stack 很难直接找到目标业务逻辑。

---

## DartPPDumper

文件：

```text
tools/DartPPDumper.lua
```

这是逆向 Reqable 时使用的 Cheat Engine Lua 辅助脚本。

主要流程：

```text
寻找匿名 RX Region
        ↓
寻找 R15 引用
        ↓
执行断点
        ↓
恢复运行时 PP
        ↓
Dump Object Pool
        ↓
识别部分 Dart Object
        ↓
反查 Object Reference
        ↓
辅助定位 Reqable 业务代码
```

当前支持的内容包括：

- 自动筛选匿名可执行 Region
- 搜索 `[r15+offset]`
- 通过动态断点恢复 R15 / PP
- Dump Dart Object Pool
- Smi / Tagged Pointer 基础识别
- Object Header / CID 基础解析
- Dart String 基础解析
- Object Pool 直接引用搜索
- Object Field 间接引用搜索

默认输出：

```text
C:\Users\Public\dart_objectpool_plus.txt
C:\Users\Public\dart_objectpool_refs.txt
```

这个工具的目的很简单：

> 在 IDA 无法直接给出 Dart 对象引用时，帮助把 `[r15+offset]` 和实际运行时对象重新对应起来。

---

## 项目结构

```text
.
├── CMakeLists.txt
├── MemMonitor.cpp
├── MemMonitor.h
├── MemoryKit.cpp
├── MemoryKit.h
├── version.def
├── version_x64.c
├── version_x64_jump.asm
├── version_x64_jump.S
│
└── tools
    └── DartPPDumper.lua
```

### `version_x64.c`

项目入口，主要负责：

- `version.dll` Proxy
- 加载系统真实 `version.dll`
- 初始化 Forwarder
- 创建工作线程
- 启动内存监控
- 对目标 AOT Region 执行 Pattern Scan
- 执行当前 Reqable 研究 Patch

### `MemMonitor.cpp`

持续检测进程中新出现的候选 AOT Code Region。

主要目的是处理 Reqable 运行过程中新增 AOT Region 的情况。

### `MemoryKit.cpp`

提供基础 Runtime Memory 操作：

- Pattern Parse
- `??` Wildcard
- Pattern Scan
- Runtime Patch
- `VirtualProtect`
- `FlushInstructionCache`

### `tools/DartPPDumper.lua`

用于辅助恢复 Dart AOT Runtime 信息并继续分析 Reqable 业务对象。

---

## 编译

在项目根目录打开 x64 Native Tools Command Prompt：

```powershell
cmake -S . -B build -A x64
cmake --build build --config Release
```

---

## Disclaimer

本项目为个人逆向工程、Flutter / Dart AOT 学习和软件安全研究记录。

Reqable 是其原开发者 / 权利人的软件，本项目与 Reqable 官方无关，也不代表 Reqable 官方立场。

请仅在你有权分析的软件、个人测试环境以及符合当地法律和软件许可协议的范围内使用本项目。

---

## Credits

DLL Proxy 部分基于 **AheadLibEx**：

```text
https://github.com/i1tao/AheadLibEx
```

Author: i1tao

---

## License

MIT
