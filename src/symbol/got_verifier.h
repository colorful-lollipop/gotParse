#pragma once

#include "core/types.h"
#include "process/maps_parser.h"
#include <string>
#include <optional>
#include <unordered_map>

namespace elf::got {

/**
 * @brief GOT hook verification methods
 *
 * Provides multiple verification strategies for detecting GOT hooking:
 * 1. Symbol name verification - Verify symbol at runtime address matches expected
 * 2. LD simulation - Calculate expected address by simulating ld.so loading
 */
class GOTVerifier {
public:
    /**
     * @brief Verification result for a GOT entry
     */
    struct VerificationResult {
        bool symbol_name_verified{false};     ///< Symbol name matches
        bool address_verified{false};         ///< Address matches expected
        std::string runtime_symbol;           ///< Symbol at runtime address
        std::uintptr_t expected_address{0};   ///< Calculated expected address
        std::string error_message;            ///< Any error that occurred

        [[nodiscard]] bool is_hooked() const noexcept {
            return !symbol_name_verified || !address_verified;
        }

        [[nodiscard]] explicit operator bool() const noexcept {
            return symbol_name_verified && address_verified;
        }
    };

    /**
     * @brief Context for verification (provides module information)
     */
    struct VerificationContext {
        pid_t pid{0};                                     ///< Process ID
        std::unordered_map<std::string, std::uintptr_t> module_bases; ///< Module base addresses
        std::vector<MemoryRegion> regions;                ///< Memory regions

        /**
         * @brief Find which module contains an address
         */
        [[nodiscard]] std::optional<std::string> find_module_for_address(
            std::uintptr_t address) const noexcept;
    };

    /**
     * @brief Verify GOT entry using symbol name comparison
     *
     * This method:
     * 1. Takes the runtime GOT value (a pointer)
     * 2. Finds which module contains that address
     * 3. Parses the module's symbol table to find the symbol at that address
     * 4. Compares with the expected symbol name
     *
     * @param entry GOT entry to verify (must have runtime_value populated)
     * @param context Verification context with module information
     * @return VerificationResult
     */
    [[nodiscard]] static VerificationResult verify_by_symbol_name(
        const GOTEntry& entry,
        const VerificationContext& context) noexcept;

    /**
     * @brief Verify GOT entry using LD simulation
     *
     * This method simulates the ld.so loading process:
     * 1. Takes the expected symbol name from GOT entry
     * 2. Finds which shared object should provide that symbol (by checking NEEDED entries)
     * 3. Parses each shared object's symbol table
     * 4. Calculates the runtime address (base + symbol value)
     * 5. Compares with the actual runtime GOT value
     *
     * @param entry GOT entry to verify
     * @param elf_path Path to the ELF file being analyzed
     * @param context Verification context with module information
     * @return VerificationResult
     */
    [[nodiscard]] static VerificationResult verify_by_ld_simulation(
        const GOTEntry& entry,
        const std::string& elf_path,
        const VerificationContext& context) noexcept;

    /**
     * @brief Verify using both methods
     *
     * Combines both symbol name verification and LD simulation.
     *
     * @param entry GOT entry to verify (must have runtime_value populated)
     * @param elf_path Path to the ELF file being analyzed
     * @param context Verification context
     * @return VerificationResult with combined verification status
     */
    [[nodiscard]] static VerificationResult verify_comprehensive(
        const GOTEntry& entry,
        const std::string& elf_path,
        const VerificationContext& context) noexcept;

private:
    GOTVerifier() = delete;
    ~GOTVerifier() = delete;

    /**
     * @brief Find symbol name at a given address in a module
     */
    [[nodiscard]] static std::string find_symbol_at_address(
        const std::string& module_path,
        std::uintptr_t address,
        std::uintptr_t module_base) noexcept;

    /**
     * @brief Find symbol definition across all NEEDED libraries
     */
    [[nodiscard]] static std::optional<std::pair<std::string, std::uintptr_t>>
    find_symbol_definition(
        const std::string& symbol_name,
        const std::string& elf_path,
        const VerificationContext& context) noexcept;

    /**
     * @brief Get list of NEEDED libraries from an ELF file
     */
    [[nodiscard]] static std::vector<std::string> get_needed_libs(
        const std::string& elf_path) noexcept;

    /**
     * @brief Find symbol in an ELF file by name
     */
    [[nodiscard]] static std::optional<std::uintptr_t> find_symbol_address(
        const std::string& elf_path,
        const std::string& symbol_name) noexcept;
};

} // namespace elf::got
