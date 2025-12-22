/**
 * @file runtime_check.cpp
 * @brief 运行时 GOT 检测示例
 *
 * 演示如何读取运行中进程的 GOT 表并检测异常
 */

#include <elf_got/elf_got.h>

#include <iostream>
#include <iomanip>
#include <unistd.h>
#include <csignal>

using namespace elf::got;

/**
 * @brief 打印内存区域信息
 */
void print_memory_region(const MemoryRegion& region) {
    std::cout << "  0x" << std::hex << std::setw(12) << std::setfill('0') << region.start
              << " - 0x" << std::setw(12) << region.end
              << " " << region.perms
              << " " << region.pathname << "\n";
}

/**
 * @brief 检查进程是否存在
 */
bool is_process_running(pid_t pid) {
    return kill(pid, 0) == 0;
}

/**
 * @brief 分析进程的 GOT 表
 */
int analyze_process_got(pid_t pid) {
    std::cout << "========================================\n";
    std::cout << "运行时 GOT 分析\n";
    std::cout << "========================================\n";
    std::cout << "PID: " << std::dec << pid << "\n\n";

    // 1. 解析进程内存映射
    std::cout << "[1] 解析进程内存映射...\n";
    auto maps_result = MapsParser::parse_ex(pid);

    if (!maps_result.success) {
        std::cerr << "  错误: " << maps_result.error_message << "\n";
        return 1;
    }

    std::cout << "  找到 " << maps_result.regions.size() << " 个内存区域\n";
    std::cout << "  找到 " << maps_result.module_bases.size() << " 个加载模块\n\n";

    // 显示主要模块
    std::cout << "  主要模块:\n";
    for (const auto& [path, base] : maps_result.module_bases) {
        if (path.empty() || path[0] == '[') continue;

        const std::string filename = path.substr(path.find_last_of('/') + 1);

        // 只显示重要模块
        if (filename.find("libc") != std::string::npos ||
            filename.find("ld-") != std::string::npos ||
            filename.find("libstdc++") != std::string::npos) {
            std::cout << "    " << std::left << std::setw(20) << filename
                      << " @ 0x" << std::hex << base << "\n";
        }
    }
    std::cout << "\n";

    // 2. 创建进程内存读取器
    std::cout << "[2] 创建进程内存读取器...\n";
    ProcessReader reader(pid);

    if (!reader.is_valid()) {
        std::cerr << "  警告: 无法直接读取进程内存\n";
        std::cerr << "  可能原因: 权限不足 (需要 ptrace 权限或 sudo)\n\n";
        std::cerr << "  将仅进行静态分析...\n\n";
    } else {
        std::cout << "  内存读取器创建成功\n\n";
    }

    // 3. 分析主程序的 GOT
    std::cout << "[3] 分析主程序 GOT 表...\n";

    // 查找主程序路径
    std::string exe_path;
    for (const auto& [path, base] : maps_result.module_bases) {
        if (path.find("(deleted)") == std::string::npos &&
            path.find("/lib/") == std::string::npos &&
            !path.empty() && path[0] == '/') {
            exe_path = path;
            break;
        }
    }

    if (exe_path.empty()) {
        // 尝试从 /proc/pid/exe 读取
        char exe_link[256];
        ssize_t len = readlink(("/proc/" + std::to_string(pid) + "/exe").c_str(), exe_link, sizeof(exe_link) - 1);
        if (len > 0) {
            exe_link[len] = '\0';
            exe_path = exe_link;
        }
    }

    if (!exe_path.empty()) {
        std::cout << "  可执行文件: " << exe_path << "\n";

        // 解析 ELF 文件
        auto got_info = ELFParser::parse(exe_path);
        if (got_info) {
            // 获取主程序基址
            auto exe_base = MapsParser::find_module_base(maps_result.regions, exe_path);
            if (exe_base) {
                std::cout << "  加载基址: 0x" << std::hex << *exe_base << "\n\n";

                // 分析 .got.plt
                if (const auto& got_plt = got_info->got_plt()) {
                    std::cout << "  [.got.plt] 表项:\n";

                    // 如果可以读取内存，填充运行时值
                    SectionInfo runtime_section = *got_plt;
                    runtime_section.base_addr = *exe_base;

                    int read_count = 0;
                    if (reader.is_valid()) {
                        read_count = reader.populate_got_runtime_values(runtime_section);
                    }

                    std::cout << "    成功读取 " << read_count << " 个运行时值\n\n";

                    // 显示前 10 个表项
                    std::cout << "    前 10 个表项:\n";
                    std::cout << "      " << std::left << std::setw(30) << "符号"
                              << " " << std::setw(16) << "文件 VA"
                              << " " << std::setw(16) << "运行时地址"
                              << " " << "值\n";

                    int count = 0;
                    for (const auto& entry : runtime_section.entries) {
                        if (entry.has_symbol && count++ < 10) {
                            std::cout << "      " << std::left << std::setw(30) << entry.symbol_name
                                      << " 0x" << std::setw(14) << entry.va;

                            const std::uintptr_t runtime_va = runtime_section.runtime_address() + entry.offset;
                            std::cout << " 0x" << std::setw(14) << runtime_va;

                            if (entry.runtime_value) {
                                std::cout << " 0x" << std::setw(14) << *entry.runtime_value;
                            } else {
                                std::cout << " " << std::setw(14) << "<未读>";
                            }
                            std::cout << "\n";
                        }
                    }
                }
            }
        }
    }

    std::cout << "\n========================================\n";
    std::cout << "分析完成!\n";
    std::cout << "========================================\n";

    return 0;
}

int main(int argc, char* argv[]) {
    pid_t target_pid = 0;

    if (argc > 1) {
        target_pid = std::atoi(argv[1]);
    } else {
        // 默认分析自身
        target_pid = getpid();
    }

    if (target_pid <= 0) {
        std::cerr << "用法: " << argv[0] << " [pid]\n";
        std::cerr << "\n示例:\n";
        std::cerr << "  " << argv[0] << "        # 分析自身\n";
        std::cerr << "  " << argv[0] << " 1234   # 分析 PID 1234\n";
        return 1;
    }

    return analyze_process_got(target_pid);
}
