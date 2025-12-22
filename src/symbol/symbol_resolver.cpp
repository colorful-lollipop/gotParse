#include "symbol_resolver.h"
#include "../core/elf_parser.h"
#include "../process/maps_parser.h"

#include <elfio/elfio.hpp>
#include <elfio/elf_types.hpp>
#include <elfio/elfio_symbols.hpp>
#include <dlfcn.h>
#include <cxxabi.h>
#include <cstring>
#include <algorithm>
#include <string>

namespace elf::got {

namespace {

/**
 * @brief Get module name from path
 */
[[nodiscard]] std::string get_module_name(const std::string& path) noexcept {
    if (path.empty()) {
        return "<unknown>";
    }
    const std::size_t pos = path.find_last_of('/');
    return (pos == std::string::npos) ? path : path.substr(pos + 1);
}

/**
 * @brief Check if a name is a C++ mangled name
 * Mangled names start with _Z (Itanium C++ ABI)
 */
[[nodiscard]] bool is_mangled(const char* name) noexcept {
    return name && name[0] == '_' && name[1] == 'Z';
}

/**
 * @brief Read symbol data directly from section
 */
struct RawElf64Sym {
    std::uint32_t st_name;
    std::uint8_t  st_info;
    std::uint8_t  st_other;
    std::uint16_t st_shndx;
    std::uint64_t st_value;
    std::uint64_t st_size;
};

struct RawElf32Sym {
    std::uint32_t st_name;
    std::uint32_t st_value;
    std::uint32_t st_size;
    std::uint8_t  st_info;
    std::uint8_t  st_other;
    std::uint16_t st_shndx;
};

/**
 * @brief Extract symbol type from st_info
 */
[[nodiscard]] constexpr unsigned char get_symbol_type(unsigned char st_info) noexcept {
    return st_info & 0xf;
}

/**
 * @brief Get symbol info by index directly from section data
 */
[[nodiscard]] bool get_symbol_by_index(
    ELFIO::elfio& reader,
    ELFIO::section* sym_section,
    ELFIO::section* str_section,
    std::size_t index,
    std::string& name_out,
    std::uintptr_t& value_out,
    std::size_t& size_out,
    unsigned char& type_out) noexcept {
    if (!sym_section || !str_section) {
        return false;
    }

    const char* strtab = static_cast<const char*>(str_section->get_data());
    const char* sym_data = sym_section->get_data();

    if (!strtab || !sym_data) {
        return false;
    }

    const std::size_t entry_size = (sym_section->get_entry_size() > 0)
        ? sym_section->get_entry_size()
        : sizeof(RawElf64Sym);

    const std::size_t sym_section_size = sym_section->get_size();
    const std::size_t sym_offset = index * entry_size;

    if (sym_offset + entry_size > sym_section_size) {
        return false;
    }

    // Read symbol based on ELF class
    if (reader.get_class() == ELFIO::ELFCLASS64) {
        const auto* sym = reinterpret_cast<const RawElf64Sym*>(sym_data + sym_offset);
        value_out = sym->st_value;
        size_out = sym->st_size;
        type_out = get_symbol_type(sym->st_info);

        if (sym->st_name > 0 && sym->st_name < str_section->get_size()) {
            name_out = strtab + sym->st_name;
        }
    } else {
        const auto* sym = reinterpret_cast<const RawElf32Sym*>(sym_data + sym_offset);
        value_out = sym->st_value;
        size_out = sym->st_size;
        type_out = get_symbol_type(sym->st_info);

        if (sym->st_name > 0 && sym->st_name < str_section->get_size()) {
            name_out = strtab + sym->st_name;
        }
    }

    return !name_out.empty();
}

} // anonymous namespace

std::string SymbolResolver::demangle(const char* mangled_name) noexcept {
    if (!mangled_name || !is_mangled(mangled_name)) {
        return mangled_name ? mangled_name : "";
    }

    int status = 0;
    char* demangled = abi::__cxa_demangle(mangled_name, nullptr, nullptr, &status);

    if (demangled) {
        std::string result(demangled);
        std::free(demangled);
        return result;
    }

    // Demangling failed, return original
    return mangled_name;
}

SymbolResolver::ResolveResult SymbolResolver::resolve_dynamic(
    void* address) noexcept {
    ResolveResult result;
    result.found = false;

    if (!address) {
        result.error_message = "Null address provided";
        return result;
    }

    Dl_info info;
    if (dladdr(address, &info) == 0) {
        result.error_message = "dladdr failed to resolve address";
        return result;
    }

    result.found = true;
    result.symbol.name = info.dli_sname ? info.dli_sname : "";
    result.symbol.address = reinterpret_cast<std::uintptr_t>(address);
    result.symbol.module_name = info.dli_fname ? info.dli_fname : "";

    // Demangle if it's a C++ symbol
    if (info.dli_sname) {
        result.symbol.demangled_name = demangle(info.dli_sname);
    }

    // Determine symbol type from binding
    if (info.dli_saddr) {
        result.symbol.type = "FUNC";  // dladdr mostly gives function info
    }

    return result;
}

SymbolResolver::ResolveResult SymbolResolver::resolve_from_elf(
    const std::string& elf_path,
    std::uintptr_t address,
    std::uintptr_t base_addr) noexcept {
    ResolveResult result;
    result.found = false;

    ELFIO::elfio reader;
    if (!reader.load(elf_path)) {
        result.error_message = "Failed to load ELF: " + elf_path;
        return result;
    }

    // Adjust address relative to base
    const std::uintptr_t relative_addr =
        (base_addr > 0) ? (address - base_addr) : address;

    // Try .dynsym first (dynamic symbols)
    ELFIO::section* dynsym = reader.sections[".dynsym"];
    ELFIO::section* symtab = reader.sections[".symtab"];
    ELFIO::section* dynstr = reader.sections[".dynstr"];

    ELFIO::section* sym_section = dynsym ? dynsym : symtab;
    ELFIO::section* str_section = dynstr ? dynstr : reader.sections[".strtab"];

    if (!sym_section || !str_section) {
        result.error_message = "No symbol sections found in ELF";
        return result;
    }

    // Get number of symbols
    const std::size_t entry_size = (sym_section->get_entry_size() > 0)
        ? sym_section->get_entry_size()
        : sizeof(RawElf64Sym);
    const std::size_t num_symbols = sym_section->get_size() / entry_size;

    // Find symbol containing the address
    for (std::size_t i = 0; i < num_symbols; ++i) {
        std::string name;
        std::uintptr_t value = 0;
        std::size_t size = 0;
        unsigned char type = 0;

        if (get_symbol_by_index(reader, sym_section, str_section,
                i, name, value, size, type)) {
            // Check if address falls within this symbol
            if (relative_addr >= value && relative_addr < value + size) {
                result.found = true;
                result.symbol.name = name;
                result.symbol.demangled_name = demangle(name);
                result.symbol.address = address;
                result.symbol.size = size;
                result.symbol.module_name = get_module_name(elf_path);

                // Set type
                switch (type) {
                    case ELFIO::STT_FUNC:
                        result.symbol.type = "FUNC";
                        break;
                    case ELFIO::STT_OBJECT:
                        result.symbol.type = "OBJECT";
                        break;
                    case ELFIO::STT_NOTYPE:
                        result.symbol.type = "NOTYPE";
                        break;
                    default:
                        result.symbol.type = "UNKNOWN";
                        break;
                }

                return result;
            }
        }
    }

    result.error_message = "No symbol found for address: 0x" +
        std::to_string(address);
    return result;
}

std::optional<SymbolInfo> SymbolResolver::find_symbol(
    const std::string& elf_path,
    const std::string& symbol_name) noexcept {
    ELFIO::elfio reader;
    if (!reader.load(elf_path)) {
        return std::nullopt;
    }

    // Try .dynsym first
    ELFIO::section* dynsym = reader.sections[".dynsym"];
    ELFIO::section* symtab = reader.sections[".symtab"];

    ELFIO::section* sym_section = dynsym ? dynsym : symtab;
    if (!sym_section) {
        return std::nullopt;
    }

    ELFIO::section* dynstr = reader.sections[".dynstr"];
    ELFIO::section* str_section = dynstr ? dynstr : reader.sections[".strtab"];

    if (!str_section) {
        return std::nullopt;
    }

    const std::size_t entry_size = (sym_section->get_entry_size() > 0)
        ? sym_section->get_entry_size()
        : sizeof(RawElf64Sym);
    const std::size_t num_symbols = sym_section->get_size() / entry_size;

    for (std::size_t i = 0; i < num_symbols; ++i) {
        std::string name;
        std::uintptr_t value = 0;
        std::size_t size = 0;
        unsigned char type = 0;

        if (get_symbol_by_index(reader, sym_section, str_section,
                i, name, value, size, type)) {
            if (name == symbol_name) {
                SymbolInfo info;
                info.name = name;
                info.demangled_name = demangle(name);
                info.address = value;
                info.size = size;
                info.module_name = get_module_name(elf_path);

                switch (type) {
                    case ELFIO::STT_FUNC:
                        info.type = "FUNC";
                        break;
                    case ELFIO::STT_OBJECT:
                        info.type = "OBJECT";
                        break;
                    case ELFIO::STT_NOTYPE:
                        info.type = "NOTYPE";
                        break;
                    default:
                        info.type = "UNKNOWN";
                        break;
                }

                return info;
            }
        }
    }

    return std::nullopt;
}

std::vector<SymbolInfo> SymbolResolver::find_symbols_matching(
    const std::string& elf_path,
    const std::string& pattern) noexcept {
    std::vector<SymbolInfo> results;

    ELFIO::elfio reader;
    if (!reader.load(elf_path)) {
        return results;
    }

    ELFIO::section* dynsym = reader.sections[".dynsym"];
    ELFIO::section* symtab = reader.sections[".symtab"];

    ELFIO::section* sym_section = dynsym ? dynsym : symtab;
    if (!sym_section) {
        return results;
    }

    ELFIO::section* dynstr = reader.sections[".dynstr"];
    ELFIO::section* str_section = dynstr ? dynstr : reader.sections[".strtab"];

    if (!str_section) {
        return results;
    }

    const std::size_t entry_size = (sym_section->get_entry_size() > 0)
        ? sym_section->get_entry_size()
        : sizeof(RawElf64Sym);
    const std::size_t num_symbols = sym_section->get_size() / entry_size;

    for (std::size_t i = 0; i < num_symbols; ++i) {
        std::string name;
        std::uintptr_t value = 0;
        std::size_t size = 0;
        unsigned char type = 0;

        if (get_symbol_by_index(reader, sym_section, str_section,
                i, name, value, size, type)) {
            if (name.find(pattern) != std::string::npos) {
                SymbolInfo info;
                info.name = name;
                info.demangled_name = demangle(name);
                info.address = value;
                info.size = size;
                info.module_name = get_module_name(elf_path);

                switch (type) {
                    case ELFIO::STT_FUNC:
                        info.type = "FUNC";
                        break;
                    case ELFIO::STT_OBJECT:
                        info.type = "OBJECT";
                        break;
                    case ELFIO::STT_NOTYPE:
                        info.type = "NOTYPE";
                        break;
                    default:
                        info.type = "UNKNOWN";
                        break;
                }

                results.push_back(std::move(info));
            }
        }
    }

    return results;
}

std::string SymbolResolver::got_entry_to_symbol(
    const std::string& module_path,
    std::size_t got_offset) noexcept {
    // Parse the module to get GOT info
    auto got_info = ELFParser::parse(module_path);
    if (!got_info) {
        return "";
    }

    // Check both .got and .got.plt
    auto check_section = [&](const std::optional<SectionInfo>& section) -> std::string {
        if (!section) {
            return "";
        }
        for (const auto& entry : section->entries) {
            if (entry.offset == got_offset && entry.has_symbol) {
                return entry.symbol_name;
            }
        }
        return "";
    };

    std::string result = check_section(got_info->got_plt());
    if (result.empty()) {
        result = check_section(got_info->got());
    }
    return result;
}

std::optional<SymbolInfo> SymbolResolver::resolve_address(
    std::uintptr_t address,
    pid_t pid) noexcept {
    // For self process, try dladdr first (fastest)
    if (pid == 0) {
        auto result = resolve_dynamic(reinterpret_cast<void*>(address));
        if (result.found) {
            return result.symbol;
        }
    }

    // Parse /proc/pid/maps to find which module contains this address
    auto maps_result = MapsParser::parse(pid);
    if (!maps_result) {
        return std::nullopt;
    }

    auto region = MapsParser::find_region(maps_result->regions, address);
    if (!region || region->pathname.empty()) {
        return std::nullopt;
    }

    // Resolve from ELF file
    const std::string& module_path = region->pathname;
    auto module_base = maps_result->find_base(module_path);

    auto result = resolve_from_elf(module_path, address,
        module_base.value_or(0));
    if (result.found) {
        return result.symbol;
    }

    return std::nullopt;
}

} // namespace elf::got
