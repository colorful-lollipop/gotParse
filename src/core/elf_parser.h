#pragma once

#include "types.h"
#include <string>
#include <optional>
#include <unordered_map>

namespace elf::got {

/**
 * @brief ELF file parser for extracting GOT information
 *
 * Provides static file parsing capabilities for ELF binaries,
 * extracting Global Offset Table (GOT) and PLT GOT sections
 * with their associated symbol information.
 */
class ELFParser {
public:
    /**
     * @brief Detailed parse result with error information
     */
    struct ParseResult {
        bool success{false};
        std::string error_message;
        std::optional<GOTInfo> got_info;

        [[nodiscard]] explicit operator bool() const noexcept {
            return success;
        }
    };

    /**
     * @brief Parse GOT sections from an ELF file
     * @param elf_path Path to the ELF file (.so or executable)
     * @return GOTInfo if successful, std::nullopt on error
     */
    [[nodiscard]] static std::optional<GOTInfo> parse(
        const std::string& elf_path) noexcept;

    /**
     * @brief Parse GOT sections with detailed error reporting
     * @param elf_path Path to the ELF file (.so or executable)
     * @return ParseResult with success status and GOT info or error
     */
    [[nodiscard]] static ParseResult parse_ex(
        const std::string& elf_path) noexcept;

    /**
     * @brief Calculate runtime virtual address for a section
     * @param base_addr Base load address of the module
     * @param section_va Section virtual address from ELF
     * @return Runtime virtual address
     */
    [[nodiscard]] static std::uintptr_t calculate_runtime_va(
        std::uintptr_t base_addr,
        std::uintptr_t section_va) noexcept {
        return base_addr + section_va;
    }

    /**
     * @brief Get the ELF class (32/64 bit) of a file
     * @param elf_path Path to the ELF file
     * @return 32 or 64, or 0 on error
     */
    [[nodiscard]] static int get_elf_class(
        const std::string& elf_path) noexcept;

    /**
     * @brief Check if a file is a valid ELF
     * @param elf_path Path to check
     * @return true if valid ELF file
     */
    [[nodiscard]] static bool is_valid_elf(
        const std::string& elf_path) noexcept;

    /**
     * @brief Extract build ID from ELF file
     * @param elf_path Path to the ELF file
     * @return Build ID as hex string, or empty if not found
     */
    [[nodiscard]] static std::string get_build_id(
        const std::string& elf_path) noexcept;

private:
    ELFParser() = delete;
    ~ELFParser() = delete;
    ELFParser(const ELFParser&) = delete;
    ELFParser& operator=(const ELFParser&) = delete;
};

} // namespace elf::got
