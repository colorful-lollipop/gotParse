#include <elf_got/elf_got.h>

#include <iostream>
#include <iomanip>
#include <sstream>
#include <cstring>
#include <memory>

namespace {

using namespace elf::got;

/**
 * @brief Print program usage
 */
void print_usage(const char* program_name) {
    std::cout << "ELF GOT Parser - Runtime Analysis Tool\n"
              << "Usage:\n"
              << "  " << program_name << " <elf_file>                     Parse ELF file and show GOT info\n"
              << "  " << program_name << " --self                          Analyze current process\n"
              << "  " << program_name << " --pid <pid>                     Analyze running process\n"
              << "  " << program_name << " --resolve <address>             Resolve address to symbol (self)\n"
              << "  " << program_name << " --resolve <address> --pid <pid> Resolve address in process\n"
              << "\nOptions:\n"
              << "  -v, --verbose    Verbose output\n"
              << "  -h, --help       Show this help\n";
}

/**
 * @brief Print a separator line
 */
void print_separator(char c = '-', std::size_t len = 80) {
    std::cout << std::string(len, c) << "\n";
}

/**
 * @brief Print GOT section info
 */
void print_got_section(const SectionInfo& section, bool verbose = false) {
    std::cout << "  Section: " << section.name << "\n"
              << "    Virtual Address (file):   0x" << std::hex << section.virtual_addr << "\n"
              << "    File Offset:              0x" << section.file_offset << "\n"
              << "    Size:                     " << std::dec << section.size << " bytes\n"
              << "    Entry Count:              " << section.entry_count() << " entries\n";

    if (section.base_addr > 0) {
        std::cout << "    Base Address:             0x" << std::hex << section.base_addr << "\n"
                  << "    Runtime Address:         0x" << section.runtime_address() << "\n";
    }
    std::cout << "\n";

    if (section.entries.empty()) {
        std::cout << "  No entries in this section.\n\n";
        return;
    }

    // Count entries with symbols
    int symbol_count = 0;
    for (const auto& entry : section.entries) {
        if (entry.has_symbol) {
            symbol_count++;
        }
    }

    if (symbol_count == 0 && !verbose) {
        std::cout << "  No symbols found (use -v for all entries).\n\n";
        return;
    }

    // Print header
    std::cout << "  " << std::left << std::setw(6)  << "Idx"
              << " " << std::right << std::setw(8)  << "Offset"
              << " " << std::setw(16) << "File VA"
              << " " << std::setw(16) << "Runtime VA";

    if (section.base_addr > 0) {
        std::cout << " " << std::setw(16) << "Value";
        std::cout << " " << std::setw(6)  << "Match";
    }

    std::cout << "  " << std::left << std::setw(30) << "Symbol"
              << "\n";

    std::cout << "  " << std::left << std::setw(6)  << "------"
              << " " << std::right << std::setw(8)  << "------"
              << " " << std::setw(16) << "----------------"
              << " " << std::setw(16) << "----------------";

    if (section.base_addr > 0) {
        std::cout << " " << std::setw(16) << "----------------";
        std::cout << " " << std::setw(6)  << "------";
    }

    std::cout << "  " << std::left << std::setw(30) << "------"
              << "\n";

    // Print entries
    int idx = 0;
    for (const auto& entry : section.entries) {
        // Skip non-symbol entries unless verbose
        if (!entry.has_symbol && !verbose) {
            continue;
        }

        std::cout << "  " << std::left << std::setw(6) << idx++
                  << " " << std::right << std::setw(8) << std::hex << entry.offset
                  << " " << std::setw(16) << entry.va;

        if (section.base_addr > 0) {
            const std::uintptr_t runtime_va = section.runtime_address() + entry.offset;
            std::cout << " " << std::setw(16) << runtime_va;

            if (entry.runtime_value) {
                std::cout << " " << std::setw(16) << *entry.runtime_value;
                std::cout << " " << std::setw(6) << (entry.address_matches ? "YES" : "NO");
            } else {
                std::cout << " " << std::setw(16) << "<unread>";
                std::cout << " " << std::setw(6) << "-";
            }
        }

        std::string symbol = entry.has_symbol ? entry.symbol_name : "<none>";
        std::cout << "  " << std::left << std::setw(30) << symbol
                  << "\n";
    }
    std::cout << "\n";
}

/**
 * @brief Analyze an ELF file
 */
int analyze_elf_file(const std::string& elf_path, bool verbose) {
    auto result = ELFParser::parse_ex(elf_path);

    if (!result.success) {
        std::cerr << "Error: " << result.error_message << "\n";
        return 1;
    }

    const auto& got_info = *result.got_info;

    print_separator('=');
    std::cout << "GOT Analysis: " << elf_path << "\n";
    print_separator('=');

    // Print .got.plt
    if (const auto& got_plt = got_info.got_plt()) {
        print_separator();
        std::cout << "[.got.plt] Function GOT (Primary Hook Target)\n";
        std::cout << "  Purpose: External function addresses resolved by PLT\n";
        std::cout << "  Hook Target: YES (commonly used for function hooking)\n";
        print_separator();
        print_got_section(*got_plt, verbose);
    }

    // Print .got
    if (const auto& got = got_info.got()) {
        print_separator('=');
        std::cout << "[.got] Data GOT\n";
        std::cout << "  Purpose: Global variable addresses\n";
        std::cout << "  Hook Target: Sometimes (for data references)\n";
        print_separator('=');
        print_got_section(*got, verbose);
    }

    return 0;
}

/**
 * @brief Analyze a running process
 */
int analyze_process(pid_t pid, bool verbose) {
    print_separator('=');
    std::cout << "Runtime GOT Analysis: ";
    std::cout << (pid == 0 ? "self process" : "PID " + std::to_string(pid));
    std::cout << "\n";
    print_separator('=');

    // Get process memory regions
    auto maps_result = MapsParser::parse_ex(pid);
    if (!maps_result.success) {
        std::cerr << "Error: Failed to parse memory maps: "
                  << maps_result.error_message << "\n";
        return 1;
    }

    std::cout << "\nLoaded modules (" << maps_result.module_bases.size() << "):\n";

    // Print executable and main libraries
    std::vector<std::string> important_modules = {
        "libc.so", "libstdc++", "libgcc_s", "ld-linux"
    };

    for (const auto& [path, base] : maps_result.module_bases) {
        // Skip special entries
        if (path.empty() || path[0] == '[') {
            continue;
        }

        const std::string filename = path.substr(path.find_last_of('/') + 1);

        // Check if this is an important module
        bool is_important = false;
        for (const auto& imp : important_modules) {
            if (filename.find(imp) != std::string::npos) {
                is_important = true;
                break;
            }
        }

        // Also show the executable
        if (filename == "elf_got" || filename.find("example") != std::string::npos) {
            is_important = true;
        }

        if (is_important || verbose) {
            std::cout << "  " << std::left << std::setw(40) << filename
                      << " @ 0x" << std::hex << base << "\n";
        }
    }
    std::cout << "\n";

    // Analyze each module's GOT
    ProcessReader reader(pid);
    if (!reader.is_valid()) {
        std::cerr << "Warning: Cannot read process memory directly.\n";
        std::cerr << "Showing file-based analysis only.\n\n";
    }

    for (const auto& [module_path, base_addr] : maps_result.module_bases) {
        if (module_path.empty() || module_path[0] == '[') {
            continue;
        }

        const std::string filename = module_path.substr(
            module_path.find_last_of('/') + 1);

        // Focus on libc and the executable for demo
        if (filename.find("libc.so") == std::string::npos &&
            filename.find("elf_got") == std::string::npos &&
            !verbose) {
            continue;
        }

        auto got_info = ELFParser::parse(module_path);
        if (!got_info) {
            continue;  // No GOT sections (static binary or stripped)
        }

        print_separator('=');
        std::cout << "Module: " << module_path << "\n";
        std::cout << "Base Address: 0x" << std::hex << base_addr << "\n";
        print_separator('=');

        // Copy and modify sections with base address and runtime values
        auto populate_section = [&](const std::optional<SectionInfo>& src) -> SectionInfo {
            if (!src) return SectionInfo{};
            SectionInfo modified = *src;
            modified.base_addr = base_addr;

            if (reader.is_valid()) {
                static_cast<void>(reader.populate_got_runtime_values(modified));
            }
            return modified;
        };

        // Create runtime GOT info with populated sections
        GOTInfo runtime_got;
        if (got_info->got_plt()) {
            runtime_got.set_got_plt(populate_section(got_info->got_plt()));
        }
        if (got_info->got()) {
            runtime_got.set_got(populate_section(got_info->got()));
        }

        // Print sections
        if (const auto& got_plt = runtime_got.got_plt()) {
            print_separator();
            std::cout << "[.got.plt] Function GOT\n";
            print_separator();
            print_got_section(*got_plt, verbose);
        }

        if (const auto& got = runtime_got.got()) {
            print_separator('=');
            std::cout << "[.got] Data GOT\n";
            print_separator('=');
            print_got_section(*got, verbose);
        }
    }

    return 0;
}

/**
 * @brief Resolve an address to a symbol
 */
int resolve_address(const std::string& addr_str, pid_t pid) {
    std::uintptr_t address = 0;

    // Parse address (support 0x prefix or decimal)
    std::istringstream iss(addr_str);
    if (addr_str.size() >= 2 && addr_str[0] == '0' &&
        (addr_str[1] == 'x' || addr_str[1] == 'X')) {
        iss >> std::hex >> address;
    } else {
        iss >> std::dec >> address;
    }

    if (address == 0) {
        std::cerr << "Error: Invalid address: " << addr_str << "\n";
        return 1;
    }

    print_separator('=');
    std::cout << "Symbol Resolution: 0x" << std::hex << address << "\n";
    print_separator('=');

    // Try dladdr first for self
    if (pid == 0) {
        auto result = SymbolResolver::resolve_dynamic(
            reinterpret_cast<void*>(address));
        if (result.found) {
            std::cout << "\n[dladdr resolution]\n";
            std::cout << "  Symbol:    " << result.symbol.display_name() << "\n";
            std::cout << "  Module:    " << result.symbol.module_name << "\n";
            std::cout << "  Type:      " << result.symbol.type << "\n";
            std::cout << "  Address:   0x" << std::hex << result.symbol.address << "\n";
            return 0;
        }
    }

    // Fall back to ELF-based resolution
    auto symbol = SymbolResolver::resolve_address(address, pid);
    if (symbol) {
        std::cout << "\n[ELF-based resolution]\n";
        std::cout << "  Symbol:    " << symbol->display_name() << "\n";
        std::cout << "  Module:    " << symbol->module_name << "\n";
        std::cout << "  Type:      " << symbol->type << "\n";
        std::cout << "  Size:      " << std::dec << symbol->size << " bytes\n";
        std::cout << "  Address:   0x" << std::hex << symbol->address << "\n";
        return 0;
    }

    std::cout << "\nNo symbol found for address 0x" << std::hex << address << "\n";

    // Show which memory region it belongs to
    auto maps_result = MapsParser::parse(pid);
    if (maps_result) {
        auto region = MapsParser::find_region(maps_result->regions, address);
        if (region) {
            std::cout << "\nMemory region:\n";
            std::cout << "  " << region->to_string() << "\n";
        }
    }

    return 1;
}

} // anonymous namespace

int main(int argc, char* argv[]) {
    bool verbose = false;
    pid_t target_pid = 0;
    std::string resolve_addr;

    // Parse arguments
    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];

        if (arg == "-h" || arg == "--help") {
            print_usage(argv[0]);
            return 0;
        } else if (arg == "-v" || arg == "--verbose") {
            verbose = true;
        } else if (arg == "--self") {
            // Default behavior, analyze self
        } else if (arg == "--pid") {
            if (i + 1 < argc) {
                target_pid = std::atoi(argv[++i]);
            } else {
                std::cerr << "Error: --pid requires an argument\n";
                return 1;
            }
        } else if (arg == "--resolve") {
            if (i + 1 < argc) {
                resolve_addr = argv[++i];
            } else {
                std::cerr << "Error: --resolve requires an argument\n";
                return 1;
            }
        } else if (arg[0] == '-') {
            std::cerr << "Error: Unknown option: " << arg << "\n";
            print_usage(argv[0]);
            return 1;
        } else {
            // Positional argument - treat as ELF file path
            // But if --resolve was specified, this is handled above
            if (!resolve_addr.empty()) {
                std::cerr << "Error: Unexpected argument after --resolve\n";
                return 1;
            }
            return analyze_elf_file(arg, verbose);
        }
    }

    // Handle modes
    if (!resolve_addr.empty()) {
        return resolve_address(resolve_addr, target_pid);
    }

    // Default: analyze self (pid = 0) or target process
    return analyze_process(target_pid, verbose);
}
