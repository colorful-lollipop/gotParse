# ELF GOT 解析器

一个功能全面的 C++ 库和命令行工具，用于分析 ELF 二进制文件中的全局偏移表（GOT）节区，支持运行时进程内存检测和符号解析。

## 简介

本工具专为安全研究人员、逆向工程师和系统程序员设计，可用于：

- **分析 ELF 二进制文件** - 解析并显示 `.got` 和 `.got.plt` 节区
- **检查运行中进程** - 从进程内存中读取 GOT 表项
- **检测 GOT Hook** - 比较文件与运行时 GOT 值，发现被修改的条目
- **符号解析** - 将内存地址映射为符号名称

## 功能特性

### ELF 文件分析
- 解析 `.got` 和 `.got.plt` 节区
- 提取每个 GOT 表项的符号信息
- 支持 32 位和 64 位 ELF 文件

### 运行时分析
- 通过 `/proc/pid/mem` 读取进程内存
- 解析 `/proc/pid/maps` 获取内存布局
- 检测运行时的 GOT 修改

### 符号解析
- 通过 `dladdr` 进行动态符号解析
- 基于 ELF 符号表的查找
- 地址到符号的映射

## 构建要求

- **CMake** 3.15 或更高版本
- **C++17** 兼容编译器（GCC 8+, Clang 7+）
- **操作系统**: Linux（使用 Linux 特定的 procfs 接口）

## 构建

```bash
# 克隆仓库
git clone https://github.com/colorful-lollipop/gotParse.git
cd gotParse

# 配置并构建
mkdir build && cd build
cmake ..
make

# 运行测试（可选）
cmake .. -DBUILD_TESTS=ON
make test
```

### 构建选项

| 选项 | 默认值 | 说明 |
|------|--------|------|
| `BUILD_TESTS` | `ON` | 构建单元测试 |
| `BUILD_EXAMPLES` | `ON` | 构建示例程序 |
| `ENABLE_COVERAGE` | `OFF` | 启用代码覆盖率报告 |
| `ENABLE_WERROR` | `OFF` | 将警告视为错误 |

### 配置示例

```bash
# Release 构建，带测试
cmake -DCMAKE_BUILD_TYPE=Release -DBUILD_TESTS=ON ..

# Debug 构建，带覆盖率
cmake -DCMAKE_BUILD_TYPE=Debug -DENABLE_COVERAGE=ON ..

# 最小化构建（无测试和示例）
cmake -DBUILD_TESTS=OFF -DBUILD_EXAMPLES=OFF ..
```

## 使用方法

### 命令行工具

```bash
# 分析 ELF 文件
./elf_got /bin/ls

# 分析当前进程
./elf_got --self

# 分析指定 PID 的进程
./elf_got --pid 1234

# 解析地址到符号
./elf_got --resolve 0x7f8a4b012345

# 详细输出（显示所有 GOT 表项）
./elf_got -v /bin/ls

# 检测 GOT hook
./elf_got --pid $(pgrep target_program)
```

### 库的使用

```cpp
#include <elf_got/elf_got.h>

using namespace elf::got;

// 解析 ELF 文件
auto got_info = ELFParser::parse("/bin/ls");
if (got_info) {
    const auto& got_plt = got_info->got_plt();
    if (got_plt) {
        for (const auto& entry : got_plt->entries) {
            std::cout << entry.symbol_name << " @ 0x"
                      << std::hex << entry.va << "\n";
        }
    }
}

// 解析进程内存映射
auto maps_result = MapsParser::parse(1234);  // PID
if (maps_result) {
    for (const auto& region : maps_result->regions) {
        std::cout << region.to_string() << "\n";
    }
}

// 读取进程内存
ProcessReader reader(1234);
if (reader.is_valid()) {
    std::vector<std::byte> buffer(0x1000);
    if (reader.read(0x7f8a4b000000, buffer.data(), buffer.size())) {
        // 处理数据...
    }
}

// 解析地址到符号
auto symbol = SymbolResolver::resolve_address(0x7f8a4b012345, 1234);
if (symbol) {
    std::cout << "符号: " << symbol->display_name() << "\n";
}
```

## 项目结构

```
gotParse/
├── include/              # 公共头文件
│   └── elf_got/
│       └── elf_got.h    # 主 API 头文件
├── src/
│   ├── core/            # 核心功能
│   │   ├── types.h/cpp           # 数据结构
│   │   └── elf_parser.h/cpp      # ELF 解析
│   ├── process/         # 进程相关
│   │   ├── maps_parser.h/cpp     # /proc/pid/maps 解析
│   │   └── process_reader.h/cpp  # 内存读取
│   ├── symbol/          # 符号解析
│   │   └── symbol_resolver.h/cpp
│   └── main.cpp         # 命令行工具
├── tests/               # 单元测试
├── examples/            # 示例程序
└── cmake/               # CMake 模块
```

## 使用场景

### 安全分析

检测恶意的 GOT 修改（hook）：

```bash
# 比较文件和运行时 GOT 值
./elf_got --pid $(pgrep 可疑程序)
```

### 逆向工程

了解程序的动态链接：

```bash
./elf_got /path/to/binary
```

### 调试

验证运行时进程中的符号解析：

```bash
./elf_got --resolve 0x地址 --pid pid
```

## API 参考

### ELFParser

| 方法 | 说明 |
|------|------|
| `parse(path)` | 解析 ELF 文件，返回 `GOTInfo` |
| `parse_ex(path)` | 扩展解析，包含详细错误信息 |

### ProcessReader

| 方法 | 说明 |
|------|------|
| `ProcessReader(pid)` | 为进程创建读取器 |
| `is_valid()` | 检查读取器是否可访问进程 |
| `read(addr, buf, size)` | 从进程读取内存 |
| `populate_got_runtime_values(section)` | 填充运行时 GOT 值 |
| `detect_hooks(section)` | 检测 GOT hook |

### MapsParser

| 方法 | 说明 |
|------|------|
| `parse(pid)` | 解析 /proc/pid/maps |
| `parse_ex(pid)` | 扩展解析，包含详细错误信息 |
| `find_region(regions, addr)` | 查找包含地址的内存区域 |

### SymbolResolver

| 方法 | 说明 |
|------|------|
| `resolve_address(addr, pid)` | 通过 ELF 解析地址 |
| `resolve_dynamic(addr)` | 通过 dladdr 解析 |

## 原理说明

### 什么是 GOT？

GOT（Global Offset Table）是 ELF 二进制文件中用于位置无关代码的数据表：

- **`.got`**: 存储全局变量的地址
- **`.got.plt`**: 存储外部函数的地址（通过 PLT 调用）

### 为什么检测 GOT？

- **GOT Hook** 是常见的代码注入技术
- 恶意软件常通过修改 GOT 表项劫持函数调用
- 检测 GOT 修改可以发现潜在的安全威胁

### 检测原理

1. 读取 ELF 文件中的原始 GOT 值
2. 从进程内存读取当前 GOT 值
3. 比较两者，发现不一致的条目

## 许可证

MIT License

## 贡献

欢迎贡献！请确保：
- 代码符合 C++17 标准
- 所有测试通过：`make test`
- 新功能包含相应的测试

## 参考资料

- [ELF 格式规范](https://refspecs.linuxfoundation.org/elf/elf.pdf)
- [GOT 和 PLT 详解](https://www.technovelty.org/linux/plt-and-got-the-painless-way.html)
- [Linux procfs 手册](https://man7.org/linux/man-pages/man5/proc.5.html)
