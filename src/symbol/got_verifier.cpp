#include "got_verifier.h"
#include "core/elf_parser.h"
#include "process/process_reader.h"

#include <elfio/elfio.hpp>
#include <algorithm>
#include <cstring>

namespace elf::got {

// ============================================================================
// VerificationContext implementation
// ============================================================================

std::optional<std::string> GOTVerifier::VerificationContext::find_module_for_address(
    std::uintptr_t address) const noexcept {
    for (const auto& region : regions) {
        if (region.contains(address) && !region.pathname.empty()) {
            return region.pathname;
        }
    }
    return std::nullopt;
}

// ============================================================================
// Symbol Name Verification
// ============================================================================

namespace {

// Raw symbol structures for direct parsing
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

} // anonymous namespace

std::string GOTVerifier::find_symbol_at_address(
    const std::string& module_path,
    std::uintptr_t address,
    std::uintptr_t module_base) noexcept {

    ELFIO::elfio reader;
    if (!reader.load(module_path)) {
        return "";
    }

    // Calculate relative address
    const std::uintptr_t relative_addr = address - module_base;

    // Try .dynsym first (dynamic symbols - most relevant for GOT)
    ELFIO::section* dynsym = reader.sections[".dynsym"];
    ELFIO::section* dynstr = reader.sections[".dynstr"];

    if (!dynsym || !dynstr) {
        // Fallback to .symtab
        dynsym = reader.sections[".symtab"];
        dynstr = reader.sections[".strtab"];
    }

    if (!dynsym || !dynstr) {
        return "";
    }

    // Get string table
    const char* strtab = static_cast<const char*>(dynstr->get_data());
    const char* sym_data = dynsym->get_data();

    if (!strtab || !sym_data) {
        return "";
    }

    // Iterate through symbols to find one containing our address
    const std::size_t entry_size = (dynsym->get_entry_size() > 0)
        ? dynsym->get_entry_size()
        : sizeof(RawElf64Sym);
    const std::size_t num_symbols = dynsym->get_size() / entry_size;

    for (std::size_t i = 0; i < num_symbols; ++i) {
        const std::size_t sym_offset = i * entry_size;
        std::uintptr_t symbol_value = 0;
        std::uintptr_t symbol_size = 0;
        std::uint32_t st_name = 0;

        // Read symbol based on ELF class
        if (reader.get_class() == ELFIO::ELFCLASS64) {
            const auto* sym = reinterpret_cast<const RawElf64Sym*>(sym_data + sym_offset);
            symbol_value = sym->st_value;
            symbol_size = sym->st_size;
            st_name = sym->st_name;
        } else {
            const auto* sym = reinterpret_cast<const RawElf32Sym*>(sym_data + sym_offset);
            symbol_value = sym->st_value;
            symbol_size = sym->st_size;
            st_name = sym->st_name;
        }

        // Check if address falls within this symbol
        if (symbol_size > 0 &&
            relative_addr >= symbol_value &&
            relative_addr < symbol_value + symbol_size) {
            if (st_name > 0 && st_name < dynstr->get_size()) {
                return strtab + st_name;
            }
        }
    }

    return "";
}

GOTVerifier::VerificationResult GOTVerifier::verify_by_symbol_name(
    const GOTEntry& entry,
    const VerificationContext& context) noexcept {

    VerificationResult result;

    if (!entry.has_symbol || entry.symbol_name.empty()) {
        result.error_message = "GOT entry has no symbol name";
        return result;
    }

    if (!entry.runtime_value || *entry.runtime_value == 0) {
        result.error_message = "No runtime value available";
        return result;
    }

    // Find which module contains the runtime address
    auto module_path_opt = context.find_module_for_address(*entry.runtime_value);
    if (!module_path_opt) {
        result.error_message = "Runtime address not in any mapped module";
        return result;
    }

    const std::string& module_path = *module_path_opt;

    // Get module base address
    auto it = context.module_bases.find(module_path);
    if (it == context.module_bases.end()) {
        result.error_message = "Module base address not found: " + module_path;
        return result;
    }
    const std::uintptr_t module_base = it->second;

    // Find symbol at runtime address
    result.runtime_symbol = find_symbol_at_address(
        module_path, *entry.runtime_value, module_base);

    if (result.runtime_symbol.empty()) {
        result.error_message = "No symbol found at runtime address";
        result.symbol_name_verified = false;
        return result;
    }

    // Compare symbol names
    result.symbol_name_verified = (result.runtime_symbol == entry.symbol_name);

    return result;
}

// ============================================================================
// LD Simulation
// ============================================================================

std::vector<std::string> GOTVerifier::get_needed_libs(
    const std::string& elf_path) noexcept {

    std::vector<std::string> needed_libs;

    ELFIO::elfio reader;
    if (!reader.load(elf_path)) {
        return needed_libs;
    }

    // Get dynamic section
    ELFIO::section* dynamic = reader.sections[".dynamic"];
    if (!dynamic) {
        return needed_libs;
    }

    // Process dynamic entries
    ELFIO::dynamic_section_accessor dynamic_accessor(reader, dynamic);

    for (std::size_t i = 0; i < dynamic_accessor.get_entries_num(); ++i) {
        ELFIO::Elf_Xword tag;
        ELFIO::Elf_Xword value;
        std::string str;

        if (dynamic_accessor.get_entry(i, tag, value, str)) {
            if (tag == ELFIO::DT_NEEDED) {
                needed_libs.push_back(str);
            }
        }
    }

    return needed_libs;
}

std::optional<std::uintptr_t> GOTVerifier::find_symbol_address(
    const std::string& elf_path,
    const std::string& symbol_name) noexcept {

    ELFIO::elfio reader;
    if (!reader.load(elf_path)) {
        return std::nullopt;
    }

    // Try .dynsym first
    ELFIO::section* dynsym = reader.sections[".dynsym"];
    if (!dynsym) {
        return std::nullopt;
    }

    ELFIO::section* dynstr = reader.sections[".dynstr"];
    if (!dynstr) {
        return std::nullopt;
    }

    ELFIO::symbol_section_accessor symbols(reader, dynsym);

    for (std::size_t i = 0; i < symbols.get_symbols_num(); ++i) {
        std::string name;
        ELFIO::Elf_Xword value;
        ELFIO::Elf_Xword size;
        unsigned char bind;
        unsigned char type;
        ELFIO::Elf_Half section_index;
        unsigned char other;

        if (symbols.get_symbol(i, name, value, size, bind, type, section_index, other)) {
            if (name == symbol_name && type == ELFIO::STT_FUNC) {
                return static_cast<std::uintptr_t>(value);
            }
        }
    }

    return std::nullopt;
}

std::optional<std::pair<std::string, std::uintptr_t>>
GOTVerifier::find_symbol_definition(
    const std::string& symbol_name,
    const std::string& elf_path,
    const VerificationContext& context) noexcept {

    // First check the main ELF file itself
    auto main_addr = find_symbol_address(elf_path, symbol_name);
    if (main_addr) {
        return std::make_pair(elf_path, *main_addr);
    }

    // Get NEEDED libraries
    auto needed_libs = get_needed_libs(elf_path);

    // Common library search paths
    const std::vector<std::string> search_paths = {
        "/lib/x86_64-linux-gnu/",
        "/lib64/",
        "/usr/lib/x86_64-linux-gnu/",
        "/usr/lib64/",
        "/lib/",
        "/usr/lib/",
    };

    // Try each NEEDED library
    for (const auto& lib : needed_libs) {
        // Try exact match from module bases first
        for (const auto& [module_path, _] : context.module_bases) {
            if (module_path.find(lib) != std::string::npos) {
                auto addr = find_symbol_address(module_path, symbol_name);
                if (addr) {
                    return std::make_pair(module_path, *addr);
                }
            }
        }

        // Try search paths
        for (const auto& base_path : search_paths) {
            const std::string full_path = base_path + lib;
            auto addr = find_symbol_address(full_path, symbol_name);
            if (addr) {
                return std::make_pair(full_path, *addr);
            }
        }
    }

    // Special case: check libc.so for common functions
    static const std::vector<std::string> libc_paths = {
        "/lib/x86_64-linux-gnu/libc.so.6",
        "/lib64/libc.so.6",
        "/usr/lib/x86_64-linux-gnu/libc.so.6",
    };

    for (const auto& libc_path : libc_paths) {
        auto addr = find_symbol_address(libc_path, symbol_name);
        if (addr) {
            return std::make_pair(libc_path, *addr);
        }
    }

    return std::nullopt;
}

GOTVerifier::VerificationResult GOTVerifier::verify_by_ld_simulation(
    const GOTEntry& entry,
    const std::string& elf_path,
    const VerificationContext& context) noexcept {

    VerificationResult result;

    if (!entry.has_symbol || entry.symbol_name.empty()) {
        result.error_message = "GOT entry has no symbol name";
        return result;
    }

    if (!entry.runtime_value || *entry.runtime_value == 0) {
        result.error_message = "No runtime value available";
        return result;
    }

    // Find symbol definition (simulating ld.so lookup)
    auto symbol_def = find_symbol_definition(entry.symbol_name, elf_path, context);

    if (!symbol_def) {
        result.error_message = "Symbol definition not found: " + entry.symbol_name;
        return result;
    }

    const auto& [def_module, symbol_value] = *symbol_def;

    // Get module base address
    auto it = context.module_bases.find(def_module);
    if (it == context.module_bases.end()) {
        result.error_message = "Module base not found: " + def_module;
        return result;
    }

    const std::uintptr_t module_base = it->second;

    // Calculate expected runtime address
    result.expected_address = module_base + symbol_value;

    // Verify address matches
    result.address_verified = (result.expected_address == *entry.runtime_value);

    return result;
}

// ============================================================================
// Comprehensive Verification
// ============================================================================

GOTVerifier::VerificationResult GOTVerifier::verify_comprehensive(
    const GOTEntry& entry,
    const std::string& elf_path,
    const VerificationContext& context) noexcept {

    VerificationResult result;

    // Run both verifications
    auto symbol_result = verify_by_symbol_name(entry, context);
    auto ld_result = verify_by_ld_simulation(entry, elf_path, context);

    // Combine results
    result.symbol_name_verified = symbol_result.symbol_name_verified;
    result.address_verified = ld_result.address_verified;
    result.runtime_symbol = symbol_result.runtime_symbol;
    result.expected_address = ld_result.expected_address;

    // Combine error messages
    if (!symbol_result.error_message.empty() && !ld_result.error_message.empty()) {
        result.error_message = "Symbol: " + symbol_result.error_message +
                              " | LD: " + ld_result.error_message;
    } else if (!symbol_result.error_message.empty()) {
        result.error_message = symbol_result.error_message;
    } else if (!ld_result.error_message.empty()) {
        result.error_message = ld_result.error_message;
    }

    return result;
}

} // namespace elf::got
