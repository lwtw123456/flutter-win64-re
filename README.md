# flutter-win64-re

> 面向 Windows x64 Flutter/Dart AOT 应用的逆向工程研究。

## 项目简介

本项目围绕 Windows x64 平台 Flutter/Dart AOT 应用开展逆向工程研究，重点关注 AOT Code Region 定位、运行时内存分析、Object Pool 恢复与 Runtime Patch 等问题。

目前包含两个研究成果：

- **Reqable**：实现了不登录即可使用原本需要订阅才能使用的功能。
- **Rive**：实现了免费用户也可以导出 `.riv` 文件。

项目主要涉及：

- Flutter Windows x64 / Dart AOT 静态分析
- 匿名 AOT Code Region 定位
- Runtime Pattern Scan
- Runtime Patch
- Dart AOT 中的 R15 / PP 分析
- Dart Object Pool Dump
- Tagged Object / Smi / String 基础识别
- `version.dll` Proxy

`DartPPDumper.lua` 是研究过程中编写的一个基于 Cheat Engine Lua 的 Dart AOT 运行时分析工具，目前已具备 PP 恢复、Object Pool Dump、对象识别、字符串解析与引用搜索等能力，并具有继续扩展为通用 Dart AOT 分析工具的潜力。

---

## Flutter / Dart AOT 逆向中的问题

Flutter Android / iOS 的公开逆向资料已经比较多，但 **Flutter Windows x64** 的研究资料和工具几乎没有，这也是本项目的研究重点。

### IDA 函数识别不完整

IDA 漏掉大量实际正在执行的 Dart AOT 代码。

因此：

- Functions Window 不完整
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

### 调用栈和静态分析都只能作为辅助

Flutter Framework、Dart Runtime 和自身业务代码混在同一套 AOT 代码中。

再加上：

- Framework 高频调用带来的大量噪音
- Dart Tagged Object
- Release AOT 优化
- 函数内联
- SDK / Engine 版本变化

单纯依赖 IDA F5、字符串 Xref 或 x64dbg Call Stack 很难直接找到目标业务逻辑。

---

## 项目结构

```text
.
├── DartPPDumper.lua
├── RiveHack/
│   ├── CMakeLists.txt
│   ├── MemoryKit.cpp
│   ├── MemoryKit.h
│   ├── version.def
│   ├── version_x64.c
│   ├── version_x64_jump.asm
│   └── version_x64_jump.S
│
└── ReqableHack/
    ├── CMakeLists.txt
    ├── MemMonitor.cpp
    ├── MemMonitor.h
    ├── MemoryKit.cpp
    ├── MemoryKit.h
    ├── version.def
    ├── version_x64.c
    ├── version_x64_jump.asm
    └── version_x64_jump.S
```

### RiveHack

Rive 的目标 Dart AOT Code Region 在 `version.dll` 加载时尚未出现。

因此工作线程会等 Flutter 主窗口出现后，再由 `MemoryKit` 扫描不属于已加载 PE 模块的匿名可执行内存并完成 Patch。

### ReqableHack

Reqable 在创建新的窗口后还会出现新的 Dart AOT Code Region，所以启动时只扫描一次并不够。

为此加入了 `MemMonitor`，持续检测新出现的候选 Region，并交给 `MemoryKit` 做 Pattern Scan 和 Patch。

### DartPPDumper.lua

Cheat Engine Lua 辅助脚本，主要用于 Dart AOT 运行时分析，包括：

- 搜索匿名可执行 Region
- 搜索 `[r15+offset]` 引用
- 通过动态断点恢复 R15 / PP
- Dump Dart Object Pool
- Smi / Tagged Pointer 基础识别
- Object Header / CID 基础解析
- Dart String 基础解析
- Object Pool / Object Field 引用搜索

---

## 编译

分别进入对应子项目目录，在 x64 Native Tools Command Prompt 中编译。

### ReqableHack

```powershell
cmake -S ReqableHack -B build/ReqableHack -A x64
cmake --build build/ReqableHack --config Release
```

### RiveHack

```powershell
cmake -S RiveHack -B build/RiveHack -A x64
cmake --build build/RiveHack --config Release
```

---

## Disclaimer

本项目为个人逆向工程、Flutter / Dart AOT 学习和软件安全研究项目。

Reqable、Rive 及相关商标、软件归其各自开发者 / 权利人所有。本项目与其官方无关，也不代表其官方立场。

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
