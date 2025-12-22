#include "maps_parser.h"

#include <fstream>
#include <sstream>
#include <algorithm>
#include <cstring>

namespace elf::got {

namespace {

/**
 * @brief Parse a hex address string
 * @param str String containing hex number (with or without 0x prefix)
 * @return Parsed value or nullopt
 */
[[nodiscard]] std::optional<std::uintptr_t> parse_hex_addr(
    const std::string& str) noexcept {
    if (str.empty()) {
        return std::nullopt;
    }

    std::size_t pos = 0;
    if (str.size() >= 2 && str[0] == '0' && (str[1] == 'x' || str[1] == 'X')) {
        pos = 2;
    }

    std::uintptr_t result = 0;
    for (; pos < str.size(); ++pos) {
        const char c = str[pos];
        result <<= 4;

        if (c >= '0' && c <= '9') {
            result |= static_cast<std::uintptr_t>(c - '0');
        } else if (c >= 'a' && c <= 'f') {
            result |= static_cast<std::uintptr_t>(c - 'a' + 10);
        } else if (c >= 'A' && c <= 'F') {
            result |= static_cast<std::uintptr_t>(c - 'A' + 10);
        } else {
            return std::nullopt;  // Invalid hex character
        }
    }

    return result;
}

/**
 * @brief Check if a path ends with a specific name
 */
[[nodiscard]] bool path_ends_with(
    const std::string& path,
    const std::string& suffix) noexcept {
    if (suffix.empty()) {
        return true;
    }
    if (path.size() < suffix.size()) {
        return false;
    }
    return path.compare(path.size() - suffix.size(), suffix.size(), suffix) == 0;
}

/**
 * @brief Extract just the filename from a path
 */
[[nodiscard]] std::string get_filename(const std::string& path) noexcept {
    const std::size_t pos = path.find_last_of('/');
    if (pos == std::string::npos) {
        return path;
    }
    return path.substr(pos + 1);
}

} // anonymous namespace

std::string MapsParser::get_maps_path(pid_t pid) noexcept {
    if (pid == 0) {
        return "/proc/self/maps";
    }
    return "/proc/" + std::to_string(static_cast<int>(pid)) + "/maps";
}

std::optional<MemoryRegion> MapsParser::parse_line(const std::string& line) noexcept {
    if (line.empty()) {
        return std::nullopt;
    }

    MemoryRegion region;
    std::istringstream iss(line);

    // Format: address perms offset dev inode pathname
    // Example: 7f1234567000-7f1234568000 rw-p 00007000 08:01 1234567 /lib/libc.so.6

    std::string addr_range;
    if (!(iss >> addr_range)) {
        return std::nullopt;
    }

    // Parse address range "start-end"
    const std::size_t dash_pos = addr_range.find('-');
    if (dash_pos == std::string::npos) {
        return std::nullopt;
    }

    const auto start = parse_hex_addr(addr_range.substr(0, dash_pos));
    const auto end = parse_hex_addr(addr_range.substr(dash_pos + 1));

    if (!start || !end || *start >= *end) {
        return std::nullopt;
    }

    region.start = *start;
    region.end = *end;

    // Parse permissions
    if (!(iss >> region.perms)) {
        return std::nullopt;
    }

    // Validate permissions format
    if (region.perms.size() < 4) {
        return std::nullopt;
    }

    // Parse offset
    std::string offset_str;
    if (!(iss >> offset_str)) {
        return std::nullopt;
    }
    const auto offset = parse_hex_addr(offset_str);
    if (!offset) {
        return std::nullopt;
    }
    region.offset = *offset;

    // Parse device (we may not need it, but need to consume it)
    if (!(iss >> region.dev)) {
        return std::nullopt;
    }

    // Parse inode
    if (!(iss >> region.inode)) {
        return std::nullopt;
    }

    // Parse pathname (rest of line)
    std::string pathname;
    if (std::getline(iss, pathname)) {
        // Trim leading whitespace
        const std::size_t first_non_ws = pathname.find_first_not_of(" \t\n\r");
        if (first_non_ws != std::string::npos) {
            pathname = pathname.substr(first_non_ws);
        }
        // Also trim any special annotations like "[heap]" "[stack]" "[vdso]"
        if (!pathname.empty() && pathname[0] == '[') {
            region.pathname = pathname;
        } else {
            region.pathname = pathname;
        }
    }

    return region;
}

std::optional<MapsParser::ParseResult> MapsParser::parse(pid_t pid) noexcept {
    ParseResult result = parse_ex(pid);
    if (result.success) {
        return result;
    }
    return std::nullopt;
}

MapsParser::ParseResult MapsParser::parse_ex(pid_t pid) noexcept {
    ParseResult result;
    result.success = false;

    const std::string maps_path = get_maps_path(pid);

    std::ifstream file(maps_path);
    if (!file.is_open()) {
        result.error_message = "Failed to open " + maps_path + ": " +
            std::string(std::strerror(errno));
        return result;
    }

    std::string line;
    std::size_t line_num = 0;

    while (std::getline(file, line)) {
        ++line_num;

        // Skip empty lines
        if (line.empty()) {
            continue;
        }

        auto region = parse_line(line);
        if (!region) {
            // Continue on error - just skip invalid lines
            continue;
        }

        result.regions.push_back(std::move(*region));
    }

    if (file.bad() && !file.eof()) {
        result.error_message = "Error reading " + maps_path + " at line " +
            std::to_string(line_num);
        result.regions.clear();
        return result;
    }

    extract_module_bases(result);

    result.success = true;
    return result;
}

void MapsParser::extract_module_bases(ParseResult& result) noexcept {
    for (const auto& region : result.regions) {
        // Skip regions without a pathname or with special names
        if (region.pathname.empty()) {
            continue;
        }

        // Skip [heap], [stack], [vdso], [vvar], [vsyscall], etc.
        if (!region.pathname.empty() && region.pathname[0] == '[') {
            continue;
        }

        // Only consider executable regions for base address
        if (!region.is_executable()) {
            continue;
        }

        // Check if we already have this module
        const auto it = result.module_bases.find(region.pathname);
        if (it == result.module_bases.end()) {
            // First occurrence - this is the base
            result.module_bases[region.pathname] = region.start;
        } else {
            // Already found - update if this has a lower address
            if (region.start < it->second) {
                it->second = region.start;
            }
        }
    }
}

std::optional<MemoryRegion> MapsParser::find_region(
    const std::vector<MemoryRegion>& regions,
    std::uintptr_t addr) noexcept {
    // Binary search for efficiency - regions are sorted by start address
    if (regions.empty()) {
        return std::nullopt;
    }

    // First try a simple linear search (for small lists)
    if (regions.size() < 32) {
        for (const auto& region : regions) {
            if (region.contains(addr)) {
                return region;
            }
        }
        return std::nullopt;
    }

    // Binary search for the potential region
    auto it = std::lower_bound(regions.begin(), regions.end(), addr,
        [](const MemoryRegion& r, std::uintptr_t a) {
            return r.end <= a;
        });

    if (it != regions.end() && it->contains(addr)) {
        return *it;
    }

    // Check previous region (might be the one)
    if (it != regions.begin()) {
        --it;
        if (it->contains(addr)) {
            return *it;
        }
    }

    return std::nullopt;
}

std::optional<std::uintptr_t> MapsParser::find_module_base(
    const std::vector<MemoryRegion>& regions,
    const std::string& module_name) noexcept {
    if (module_name.empty()) {
        return std::nullopt;
    }

    std::optional<std::uintptr_t> result;
    const bool is_path = module_name.find('/') != std::string::npos;

    for (const auto& region : regions) {
        // Skip special regions
        if (!region.pathname.empty() && region.pathname[0] == '[') {
            continue;
        }

        bool matches = false;
        if (is_path) {
            // Full or partial path match
            if (path_ends_with(region.pathname, module_name)) {
                matches = true;
            }
        } else {
            // Just filename match
            if (get_filename(region.pathname) == module_name) {
                matches = true;
            }
        }

        if (matches && region.is_executable()) {
            if (!result || region.start < *result) {
                result = region.start;
            }
        }
    }

    return result;
}

std::vector<MemoryRegion> MapsParser::find_module_regions(
    const std::vector<MemoryRegion>& regions,
    const std::string& module_path) noexcept {
    std::vector<MemoryRegion> result;

    if (module_path.empty()) {
        return result;
    }

    const bool is_path = module_path.find('/') != std::string::npos;

    for (const auto& region : regions) {
        if (region.pathname.empty()) {
            continue;
        }

        bool matches = false;
        if (is_path) {
            matches = path_ends_with(region.pathname, module_path);
        } else {
            matches = get_filename(region.pathname) == module_path;
        }

        if (matches) {
            result.push_back(region);
        }
    }

    return result;
}

} // namespace elf::got
