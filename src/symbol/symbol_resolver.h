#pragma once

#include "../core/types.h"
#include <optional>
#include <string>
#include <cstdint>

namespace elf::got {

/**
 * @brief Symbol resolution utilities
 *
 * Provides multiple methods for resolving symbols:
 * - Dynamic linker (dladdr) for runtime symbols
 * - ELF file parsing for static symbol lookup
 * - C++ demangling support
 */
class SymbolResolver {
public:
    /**
     * @brief Result of symbol resolution
     */
    struct ResolveResult {
        bool found{false};
        SymbolInfo symbol;
        std::string error_message;

        [[nodiscard]] explicit operator bool() const noexcept {
            return found;
        }
    };

    /**
     * @brief Resolve symbol using dladdr (dynamic linker)
     * @param address Address to resolve
     * @return ResolveResult with symbol information
     */
    [[nodiscard]] static ResolveResult resolve_dynamic(
        void* address) noexcept;

    /**
     * @brief Resolve symbol by parsing ELF file
     * @param elf_path Path to ELF file
     * @param address Virtual address to resolve
     * @param base_addr Base load address (0 if not rebased)
     * @return ResolveResult with symbol information
     */
    [[nodiscard]] static ResolveResult resolve_from_elf(
        const std::string& elf_path,
        std::uintptr_t address,
        std::uintptr_t base_addr = 0) noexcept;

    /**
     * @brief Find symbol by name in ELF file
     * @param elf_path Path to ELF file
     * @param symbol_name Symbol name to find
     * @return SymbolInfo or nullopt
     */
    [[nodiscard]] static std::optional<SymbolInfo> find_symbol(
        const std::string& elf_path,
        const std::string& symbol_name) noexcept;

    /**
     * @brief Find all symbols matching a pattern
     * @param elf_path Path to ELF file
     * @param pattern Substring pattern to match
     * @return Vector of matching symbols
     */
    [[nodiscard]] static std::vector<SymbolInfo> find_symbols_matching(
        const std::string& elf_path,
        const std::string& pattern) noexcept;

    /**
     * @brief Demangle C++ symbol name
     * @param mangled_name Mangled name (e.g., _Z3fooi)
     * @return Demangled name or original if not C++ mangled
     */
    [[nodiscard]] static std::string demangle(
        const char* mangled_name) noexcept;

    /**
     * @brief Demangle C++ symbol name (string version)
     */
    [[nodiscard]] static std::string demangle(
        const std::string& mangled_name) noexcept {
        return demangle(mangled_name.c_str());
    }

    /**
     * @brief Get the symbol name for a GOT entry in a specific module
     * @param module_path Path to the .so or executable
     * @param got_offset Offset of GOT entry in module
     * @return Symbol name or empty
     */
    [[nodiscard]] static std::string got_entry_to_symbol(
        const std::string& module_path,
        std::size_t got_offset) noexcept;

    /**
     * @brief Resolve address in running process to symbol
     * @param address Virtual address to resolve
     * @param pid Process ID (0 for self)
     * @return SymbolInfo or nullopt
     */
    [[nodiscard]] static std::optional<SymbolInfo> resolve_address(
        std::uintptr_t address,
        pid_t pid = 0) noexcept;

private:
    SymbolResolver() = delete;
    ~SymbolResolver() = delete;
    SymbolResolver(const SymbolResolver&) = delete;
    SymbolResolver& operator=(const SymbolResolver&) = delete;
};

} // namespace elf::got
