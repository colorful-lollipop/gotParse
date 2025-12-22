#pragma once

#include "core/types.h"
#include <optional>
#include <string>
#include <vector>
#include <unordered_map>
#include <cstdint>

namespace elf::got {

/**
 * @brief Parser for /proc/[pid]/maps files
 *
 * Parses the Linux /proc filesystem memory maps to extract:
 * - Memory region boundaries
 * - Permissions
 * - Mapped file paths
 * - Module base addresses
 */
class MapsParser {
public:
    /**
     * @brief Detailed parse result
     */
    struct ParseResult {
        bool success{false};
        std::string error_message;
        std::vector<MemoryRegion> regions;
        std::unordered_map<std::string, std::uintptr_t> module_bases;

        [[nodiscard]] explicit operator bool() const noexcept {
            return success;
        }

        /**
         * @brief Find module base address by path
         */
        [[nodiscard]] std::optional<std::uintptr_t> find_base(
            const std::string& module_path) const noexcept {
            const auto it = module_bases.find(module_path);
            if (it != module_bases.end()) {
                return it->second;
            }
            return std::nullopt;
        }
    };

    /**
     * @brief Parse /proc/self/maps or /proc/{pid}/maps
     * @param pid Process ID (0 for self)
     * @return Parsed memory regions or nullopt on error
     */
    [[nodiscard]] static std::optional<ParseResult> parse(pid_t pid = 0) noexcept;

    /**
     * @brief Parse with detailed error reporting
     * @param pid Process ID (0 for self)
     * @return ParseResult with error details
     */
    [[nodiscard]] static ParseResult parse_ex(pid_t pid = 0) noexcept;

    /**
     * @brief Find region containing an address
     * @param regions Vector of memory regions to search
     * @param addr Address to locate
     * @return Region containing address, or nullopt
     */
    [[nodiscard]] static std::optional<MemoryRegion> find_region(
        const std::vector<MemoryRegion>& regions,
        std::uintptr_t addr) noexcept;

    /**
     * @brief Find base address of a module
     * @param regions Vector of memory regions
     * @param module_name Module name or path (can be partial)
     * @return Base address or nullopt
     */
    [[nodiscard]] static std::optional<std::uintptr_t> find_module_base(
        const std::vector<MemoryRegion>& regions,
        const std::string& module_name) noexcept;

    /**
     * @brief Find all regions for a specific module
     * @param regions Vector of memory regions
     * @param module_path Full or partial path of module
     * @return Vector of regions belonging to the module
     */
    [[nodiscard]] static std::vector<MemoryRegion> find_module_regions(
        const std::vector<MemoryRegion>& regions,
        const std::string& module_path) noexcept;

    /**
     * @brief Get the path to /proc/[pid]/maps
     * @param pid Process ID (0 for self)
     * @return Path string
     */
    [[nodiscard]] static std::string get_maps_path(pid_t pid = 0) noexcept;

    /**
     * @brief Parse a single line from /proc/pid/maps
     * @param line Line to parse
     * @return Parsed region or nullopt
     */
    [[nodiscard]] static std::optional<MemoryRegion> parse_line(
        const std::string& line) noexcept;

private:
    MapsParser() = delete;
    ~MapsParser() = delete;
    MapsParser(const MapsParser&) = delete;
    MapsParser& operator=(const MapsParser&) = delete;

    /**
     * @brief Extract module base addresses from regions
     */
    static void extract_module_bases(ParseResult& result) noexcept;
};

} // namespace elf::got
