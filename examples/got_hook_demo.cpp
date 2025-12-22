/**
 * @file got_hook_demo.cpp
 * @brief GOT Hook 演示和检测
 *
 * 这个程序演示:
 * 1. 如何 hook GOT 表项
 * 2. 如何检测 GOT hook
 * 3. 验证 GOT hook 检测功能
 *
 * 警告: 这仅用于教育和测试目的!
 */

#include <elf_got/elf_got.h>

#include <iostream>
#include <iomanip>
#include <cstring>
#include <unistd.h>
#include <sys/mman.h>
#include <dlfcn.h>

using namespace elf::got;

// ============================================================================
// 原始函数 (被 hook 的目标)
// ============================================================================

/**
 * @brief 一个简单的函数，返回固定字符串
 * 我们将 hook 这个函数来演示 GOT 修改
 */
extern "C" {
    // 声明一个弱符号函数，便于演示
    __attribute__((weak))
    const char* get_greeting() {
        return "Hello from original function!";
    }
}

// ============================================================================
// Hook 函数
// ============================================================================

/**
 * @brief Hook 函数 - 替换原始函数
 */
const char* hooked_get_greeting() {
    return "Hello from HOOKED function! GOT was modified!";
}

// ============================================================================
// GOT Hook 工具函数
// ============================================================================

/**
 * @brief 获取当前进程的基址
 */
std::uintptr_t get_self_base_address() {
    auto maps_result = MapsParser::parse(0);  // self
    if (!maps_result) {
        return 0;
    }

    // 查找包含当前代码的模块
    const std::uintptr_t addr = reinterpret_cast<std::uintptr_t>(&get_self_base_address);
    for (const auto& region : maps_result->regions) {
        if (region.contains(addr) && !region.pathname.empty()) {
            // 返回该模块的基址
            auto base = MapsParser::find_module_base(maps_result->regions, region.pathname);
            if (base) {
                std::cout << "  找到模块: " << region.pathname << " @ 0x" << std::hex << *base << "\n";
                return *base;
            }
        }
    }

    return 0;
}

/**
 * @brief 查找并 hook GOT 中的指定函数
 *
 * @param symbol_name 要 hook 的函数符号名
 * @param new_function 替换的函数地址
 * @return 是否成功 hook
 */
bool hook_got_entry(const std::string& symbol_name, void* new_function) {
    // 1. 获取自身程序的路径
    char exe_path[256];
    ssize_t len = readlink("/proc/self/exe", exe_path, sizeof(exe_path) - 1);
    if (len <= 0) {
        std::cerr << "  错误: 无法获取可执行文件路径\n";
        return false;
    }
    exe_path[len] = '\0';

    std::cout << "[1] 解析 ELF 文件: " << exe_path << "\n";

    // 2. 解析 ELF 文件获取 GOT 信息
    auto got_info = ELFParser::parse(exe_path);
    if (!got_info) {
        std::cerr << "  错误: 无法解析 GOT 表\n";
        return false;
    }

    // 3. 获取进程基址
    const std::uintptr_t base_addr = get_self_base_address();
    if (base_addr == 0) {
        std::cerr << "  错误: 无法获取基址\n";
        return false;
    }

    std::cout << "  基址: 0x" << std::hex << base_addr << "\n\n";

    // 4. 在 .got.plt 中查找目标符号
    SectionInfo* target_section = nullptr;

    if (got_info->got_plt() && got_info->got_plt()->has_symbols()) {
        target_section = const_cast<SectionInfo*>(&(*got_info->got_plt()));
    }

    if (!target_section) {
        std::cerr << "  错误: 未找到 .got.plt 节区\n";
        return false;
    }

    target_section->base_addr = base_addr;

    std::cout << "[2] 在 GOT 中查找符号: " << symbol_name << "\n";

    std::uintptr_t* got_entry_addr = nullptr;

    for (auto& entry : target_section->entries) {
        if (entry.has_symbol && entry.symbol_name == symbol_name) {
            const std::uintptr_t runtime_va = target_section->runtime_address() + entry.offset;
            got_entry_addr = reinterpret_cast<std::uintptr_t*>(runtime_va);

            std::cout << "  找到符号 " << symbol_name << " @ 0x" << std::hex << runtime_va << "\n";
            std::cout << "  当前值: 0x" << *got_entry_addr << "\n";
            break;
        }
    }

    if (!got_entry_addr) {
        std::cerr << "  错误: 未找到符号 " << symbol_name << "\n";
        return false;
    }

    std::cout << "\n";

    // 5. 修改内存保护并写入新地址
    std::cout << "[3] 修改 GOT 表项...\n";

    // 获取页大小
    const std::size_t page_size = sysconf(_SC_PAGESIZE);
    const std::uintptr_t page_start = reinterpret_cast<std::uintptr_t>(got_entry_addr) & ~(page_size - 1);

    // 修改内存保护为可写
    if (mprotect(reinterpret_cast<void*>(page_start), page_size * 2, PROT_READ | PROT_WRITE) != 0) {
        std::cerr << "  错误: mprotect 失败: " << strerror(errno) << "\n";
        return false;
    }

    // 保存原始地址
    const std::uintptr_t original_addr = *got_entry_addr;

    // 写入新地址
    *got_entry_addr = reinterpret_cast<std::uintptr_t>(new_function);

    // 恢复内存保护
    mprotect(reinterpret_cast<void*>(page_start), page_size * 2, PROT_READ);

    std::cout << "  原始地址: 0x" << std::hex << original_addr << "\n";
    std::cout << "  新地址:   0x" << reinterpret_cast<std::uintptr_t>(new_function) << "\n";
    std::cout << "  GOT hook 成功!\n\n";

    return true;
}

// ============================================================================
// GOT Hook 检测函数
// ============================================================================

/**
 * @brief Hook 检测结果
 */
struct HookDetectionResult {
    std::string symbol_name;
    std::uintptr_t got_entry_addr;
    std::uintptr_t file_value;      // 文件中的值
    std::uintptr_t runtime_value;   // 运行时内存中的值
    bool is_hooked;                 // 是否被 hook
};

/**
 * @brief 检测 GOT hook
 *
 * 原理: 比较 ELF 文件中的 GOT 值和运行时内存中的值
 * 如果不一致，可能表示 GOT 被 hook
 */
std::vector<HookDetectionResult> detect_got_hooks() {
    std::vector<HookDetectionResult> results;

    // 1. 获取可执行文件路径
    char exe_path[256];
    ssize_t len = readlink("/proc/self/exe", exe_path, sizeof(exe_path) - 1);
    if (len <= 0) {
        std::cerr << "错误: 无法获取可执行文件路径\n";
        return results;
    }
    exe_path[len] = '\0';

    // 2. 解析 ELF 文件
    auto got_info = ELFParser::parse(exe_path);
    if (!got_info) {
        std::cerr << "错误: 无法解析 GOT 表\n";
        return results;
    }

    // 3. 获取基址
    const std::uintptr_t base_addr = get_self_base_address();
    if (base_addr == 0) {
        return results;
    }

    // 4. 读取运行时 GOT 值
    ProcessReader reader(0);
    if (!reader.is_valid()) {
        std::cerr << "错误: 无法读取进程内存\n";
        return results;
    }

    // 5. 检查 .got.plt
    if (const auto& got_plt = got_info->got_plt()) {
        SectionInfo runtime_section = *got_plt;
        runtime_section.base_addr = base_addr;
        reader.populate_got_runtime_values(runtime_section);

        for (const auto& entry : runtime_section.entries) {
            if (!entry.has_symbol || !entry.runtime_value) {
                continue;
            }

            HookDetectionResult result;
            result.symbol_name = entry.symbol_name;
            result.got_entry_addr = runtime_section.runtime_address() + entry.offset;
            result.runtime_value = *entry.runtime_value;
            result.file_value = entry.va;  // 简化处理

            // 检测 hook: 运行时值与文件值不一致
            // 注意: 这是一个简化的检测，实际情况更复杂
            // 因为动态链接器会在运行时更新 GOT 值
            result.is_hooked = (result.runtime_value != result.file_value &&
                               result.runtime_value != 0);

            results.push_back(std::move(result));
        }
    }

    return results;
}

/**
 * @brief 打印 hook 检测结果
 */
void print_hook_detection_results(const std::vector<HookDetectionResult>& results) {
    std::cout << "\n========================================\n";
    std::cout << "GOT Hook 检测结果\n";
    std::cout << "========================================\n\n";

    std::cout << "检查了 " << results.size() << " 个 GOT 表项\n\n";

    int hooked_count = 0;
    for (const auto& result : results) {
        if (result.is_hooked) {
            hooked_count++;
        }
    }

    std::cout << "可能被 Hook 的表项: " << hooked_count << "\n\n";

    std::cout << std::left << std::setw(25) << "符号"
              << " " << std::setw(16) << "GOT 地址"
              << " " << std::setw(16) << "运行时值"
              << " " << "状态\n";
    std::cout << std::string(70, '-') << "\n";

    for (const auto& result : results) {
        std::cout << std::left << std::setw(25) << result.symbol_name
                  << " 0x" << std::setw(14) << std::hex << result.got_entry_addr
                  << " 0x" << std::setw(14) << result.runtime_value
                  << " " << (result.is_hooked ? "[可能被 Hook]" : "[正常]")
                  << "\n";
    }

    std::cout << "\n========================================\n";
}

// ============================================================================
// 主函数
// ============================================================================

int main(int argc, char* argv[]) {
    std::cout << "========================================\n";
    std::cout << "GOT Hook 演示和检测\n";
    std::cout << "========================================\n\n";

    // 检查是否演示 hook
    bool demo_hook = true;
    if (argc > 1 && std::string(argv[1]) == "--detect-only") {
        demo_hook = false;
    }

    // 首先调用原始函数
    std::cout << "初始状态:\n";
    std::cout << "  get_greeting() 返回: \"" << get_greeting() << "\"\n\n";

    if (demo_hook) {
        std::cout << "\n----------------------------------------\n";
        std::cout << "步骤 1: 执行 GOT Hook\n";
        std::cout << "----------------------------------------\n\n";

        // 尝试 hook get_greeting 函数
        // 注意: 由于编译器优化和链接方式，这可能不总是有效
        // 这是一个演示性的例子
        bool success = hook_got_entry("get_greeting", reinterpret_cast<void*>(&hooked_get_greeting));

        if (success) {
            std::cout << "\n调用 hook 后的函数:\n";
            std::cout << "  get_greeting() 返回: \"" << get_greeting() << "\"\n";
            std::cout << "\n注意: 如果字符串仍然是 'original'，\n";
            std::cout << "可能是因为编译器内联了函数调用或使用了不同的链接方式。\n";
        } else {
            std::cout << "\nHook 演示失败，但仍然可以进行检测演示。\n";
        }
    }

    // 执行 hook 检测
    std::cout << "\n\n----------------------------------------\n";
    std::cout << "步骤 2: 检测 GOT Hook\n";
    std::cout << "----------------------------------------\n";

    auto results = detect_got_hooks();
    print_hook_detection_results(results);

    std::cout << "\n说明:\n";
    std::cout << "  - 这个程序演示了 GOT hook 的原理和检测方法\n";
    std::cout << "  - 实际检测需要更复杂的逻辑，因为动态链接器\n";
    std::cout << "    会在运行时更新 GOT 表项\n";
    std::cout << "  - 真正的检测应该对比预期的函数地址\n";
    std::cout << "========================================\n";

    return 0;
}
