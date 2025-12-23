#pragma once

#include "core/types.h"
#include "process/maps_parser.h"
#include "symbol/got_verifier.h"
#include <optional>
#include <vector>
#include <cstdint>
#include <cstddef>
#include <string>

namespace elf::got {

/**
 * @brief Reader for process memory via /proc/[pid]/mem
 *
 * Provides safe memory reading capabilities for analyzing
 * running processes, including self-analysis.
 */
class ProcessReader {
public:
    /**
     * @brief Error codes for memory read operations
     */
    enum class ReadError {
        None,               ///< No error
        PermissionDenied,   ///< Insufficient permissions
        InvalidAddress,     ///< Address not mapped or inaccessible
        ProcessNotFound,    ///< Process does not exist
        BufferTooSmall,     ///< Output buffer too small
        Unknown             ///< Unknown error
    };

    /**
     * @brief Result of a memory read operation
     */
    struct ReadResult {
        bool success{false};
        std::vector<std::byte> data;
        ReadError error{ReadError::None};
        std::string error_message;

        [[nodiscard]] explicit operator bool() const noexcept {
            return success;
        }
    };

    /**
     * @brief Construct a reader for a process
     * @param pid Process ID (0 = self process)
     */
    explicit ProcessReader(pid_t pid = 0) noexcept;

    /**
     * @brief Destructor - closes file descriptor
     */
    ~ProcessReader() noexcept;

    // Non-copyable, movable
    ProcessReader(const ProcessReader&) = delete;
    ProcessReader& operator=(const ProcessReader&) = delete;
    ProcessReader(ProcessReader&& other) noexcept;
    ProcessReader& operator=(ProcessReader&& other) noexcept;

    /**
     * @brief Check if reader is valid (process exists, accessible)
     */
    [[nodiscard]] bool is_valid() const noexcept {
        return mem_fd_ >= 0;
    }

    /**
     * @brief Get process ID
     */
    [[nodiscard]] pid_t pid() const noexcept {
        return pid_;
    }

    /**
     * @brief Read memory at address
     * @param address Virtual address to read from
     * @param size Number of bytes to read
     * @return ReadResult with data or error
     */
    [[nodiscard]] ReadResult read(
        std::uintptr_t address,
        std::size_t size) noexcept;

    /**
     * @brief Read a single pointer-sized value
     */
    [[nodiscard]] std::optional<std::uintptr_t> read_pointer(
        std::uintptr_t address) noexcept;

    /**
     * @brief Read GOT entry value (pointer-sized)
     * @param got_entry_va Virtual address of GOT entry
     * @return Value or nullopt on error
     */
    [[nodiscard]] std::optional<std::uintptr_t> read_got_entry(
        std::uintptr_t got_entry_va) noexcept;

    /**
     * @brief Read entire GOT section
     * @param base_va Base virtual address of GOT section
     * @param entry_count Number of entries (pointers) in section
     * @return Vector of pointer values
     */
    [[nodiscard]] std::vector<std::uintptr_t> read_got_section(
        std::uintptr_t base_va,
        std::size_t entry_count) noexcept;

    /**
     * @brief Get cached memory regions (lazy loaded)
     * @return Vector of memory regions or nullopt on error
     */
    [[nodiscard]] const std::optional<std::vector<MemoryRegion>>& regions()
        const noexcept {
        return cached_regions_;
    }

    /**
     * @brief Refresh cached memory regions
     */
    [[nodiscard]] bool refresh_regions() noexcept;

    /**
     * @brief Get module base addresses
     * @return Map of module path -> base address
     */
    [[nodiscard]] std::unordered_map<std::string, std::uintptr_t>
    get_module_bases() noexcept;

    /**
     * @brief Find region containing an address
     */
    [[nodiscard]] std::optional<MemoryRegion> find_region(
        std::uintptr_t addr) const noexcept;

    /**
     * @brief Find base address of a module
     * @param module_name Module name or path
     * @return Base address or nullopt
     */
    [[nodiscard]] std::optional<std::uintptr_t> find_module_base(
        const std::string& module_name) const noexcept;

    /**
     * @brief Read GOT entries and populate runtime values in SectionInfo
     * @param section SectionInfo to populate (must have base_addr set)
     * @return Number of entries successfully read
     */
    [[nodiscard]] std::size_t populate_got_runtime_values(
        SectionInfo& section) noexcept;

    /**
     * @brief Get error string for error code
     */
    [[nodiscard]] static const char* error_to_string(ReadError error) noexcept;

    /**
     * @brief Verify a GOT entry using symbol name comparison
     * @param entry GOT entry to verify (must have runtime_value populated)
     * @param context Verification context
     * @return Verification result
     */
    [[nodiscard]] GOTVerifier::VerificationResult verify_got_entry_symbol(
        const GOTEntry& entry,
        const GOTVerifier::VerificationContext& context) const noexcept;

    /**
     * @brief Verify a GOT entry using LD simulation
     * @param entry GOT entry to verify
     * @param elf_path Path to the ELF file being analyzed
     * @param context Verification context
     * @return Verification result
     */
    [[nodiscard]] GOTVerifier::VerificationResult verify_got_entry_ld(
        const GOTEntry& entry,
        const std::string& elf_path,
        const GOTVerifier::VerificationContext& context) const noexcept;

    /**
     * @brief Verify a GOT entry using both methods
     * @param entry GOT entry to verify (will be updated with results)
     * @param elf_path Path to the ELF file being analyzed
     * @param context Verification context
     * @return Verification result
     */
    [[nodiscard]] GOTVerifier::VerificationResult verify_got_entry(
        GOTEntry& entry,
        const std::string& elf_path,
        const GOTVerifier::VerificationContext& context) const noexcept;

    /**
     * @brief Create verification context from current process state
     * @return VerificationContext with module info
     */
    [[nodiscard]] GOTVerifier::VerificationContext create_verification_context() const noexcept;

private:
    pid_t pid_;
    int mem_fd_;
    mutable std::optional<std::vector<MemoryRegion>> cached_regions_;

    /**
     * @brief Open /proc/pid/mem file descriptor
     */
    [[nodiscard]] bool open_mem_fd() noexcept;

    /**
     * @brief Close file descriptor
     */
    void close_fd() noexcept;
};

} // namespace elf::got
