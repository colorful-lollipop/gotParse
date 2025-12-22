/**
 * @file basic_parse.cpp
 * @brief 基本的 ELF GOT 解析示例
 *
 * 演示如何使用库解析 ELF 文件的 GOT 表
 */

#include <elf_got/elf_got.h>

#include <iostream>
#include <iomanip>

using namespace elf::got;

/**
 * @brief 打印 GOT 节区信息
 */
void print_got_section(const SectionInfo& section) {
    std::cout << "  节区: " << section.name << "\n";
    std::cout << "    虚拟地址: 0x" << std::hex << section.virtual_addr << "\n";
    std::cout << "    文件偏移: 0x" << section.file_offset << "\n";
    std::cout << "    大小: " << std::dec << section.size << " 字节\n";
    std::cout << "    表项数量: " << section.entry_count() << "\n";

    // 统计有符号的表项
    int symbol_count = 0;
    for (const auto& entry : section.entries) {
        if (entry.has_symbol) {
            symbol_count++;
        }
    }
    std::cout << "    有符号的表项: " << symbol_count << "\n\n";

    // 打印前 10 个有符号的表项
    std::cout << "    前 10 个符号:\n";
    int count = 0;
    for (const auto& entry : section.entries) {
        if (entry.has_symbol && count++ < 10) {
            std::cout << "      [" << std::setw(2) << (count - 1) << "] "
                      << entry.symbol_name
                      << " @ 0x" << std::hex << entry.va << "\n";
        }
    }
    if (symbol_count > 10) {
        std::cout << "      ... 还有 " << (symbol_count - 10) << " 个符号\n";
    }
    std::cout << "\n";
}

/**
 * @brief 主函数 - 解析指定 ELF 文件的 GOT
 */
int main(int argc, char* argv[]) {
    if (argc < 2) {
        std::cout << "用法: " << argv[0] << " <elf_file>\n";
        std::cout << "\n示例:\n";
        std::cout << "  " << argv[0] << " /bin/ls\n";
        std::cout << "  " << argv[0] << " /usr/lib/x86_64-linux-gnu/libc.so.6\n";
        return 1;
    }

    const std::string elf_path = argv[1];

    std::cout << "========================================\n";
    std::cout << "ELF GOT 解析示例\n";
    std::cout << "========================================\n";
    std::cout << "文件: " << elf_path << "\n\n";

    // 检查文件是否为有效的 ELF
    if (!ELFParser::is_valid_elf(elf_path)) {
        std::cerr << "错误: 不是有效的 ELF 文件\n";
        return 1;
    }

    // 获取 ELF 类 (32/64 位)
    const int elf_class = ELFParser::get_elf_class(elf_path);
    std::cout << "ELF 类: " << elf_class << " 位\n";

    // 获取 Build ID
    const std::string build_id = ELFParser::get_build_id(elf_path);
    if (!build_id.empty()) {
        std::cout << "Build ID: " << build_id << "\n";
    }
    std::cout << "\n";

    // 解析 GOT
    auto result = ELFParser::parse_ex(elf_path);

    if (!result.success) {
        std::cerr << "解析失败: " << result.error_message << "\n";
        return 1;
    }

    const auto& got_info = *result.got_info;

    // 打印 .got.plt (函数 GOT)
    if (const auto& got_plt = got_info.got_plt()) {
        std::cout << "----------------------------------------\n";
        std::cout << "[.got.plt] 函数 GOT 表\n";
        std::cout << "  用途: 存储外部函数的地址\n";
        std::cout << "  Hook 风险: 高 (常用作函数 hook 目标)\n";
        std::cout << "----------------------------------------\n";
        print_got_section(*got_plt);
    }

    // 打印 .got (数据 GOT)
    if (const auto& got = got_info.got()) {
        std::cout << "----------------------------------------\n";
        std::cout << "[.got] 数据 GOT 表\n";
        std::cout << "  用途: 存储全局变量的地址\n";
        std::cout << "  Hook 风险: 中 (偶尔用于数据引用 hook)\n";
        std::cout << "----------------------------------------\n";
        print_got_section(*got);
    }

    std::cout << "========================================\n";
    std::cout << "解析完成!\n";
    std::cout << "========================================\n";

    return 0;
}
