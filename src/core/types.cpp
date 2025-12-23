#include "types.h"
#include <iomanip>
#include <sstream>

namespace elf::got {

std::string GOTEntry::to_string() const {
    std::ostringstream oss;
    oss << "GOTEntry{offset=0x" << std::hex << offset
        << ", va=0x" << va
        << ", symbol=" << (has_symbol ? symbol_name : "<none>")
        << ", runtime=";
    if (runtime_value) {
        oss << "0x" << *runtime_value;
        oss << ", matches=" << (address_matches ? "yes" : "no");
        // Extended verification info
        if (!runtime_symbol_name.empty()) {
            oss << ", runtime_symbol=" << runtime_symbol_name;
            oss << ", symbol_matches=" << (symbol_name_matches ? "yes" : "no");
        }
        if (expected_address) {
            oss << ", expected=0x" << *expected_address;
            oss << ", hooked=" << (address_is_hooked ? "YES" : "no");
        }
    } else {
        oss << "<unread>";
    }
    oss << std::dec << "}";
    return oss.str();
}

std::string MemoryRegion::to_string() const {
    std::ostringstream oss;
    oss << "MemoryRegion{0x" << std::hex << start
        << "-0x" << end
        << ", " << perms
        << ", offset=0x" << offset
        << ", " << dev
        << ", inode=" << std::dec << inode;
    if (!pathname.empty()) {
        oss << ", path=" << pathname;
    }
    oss << "}";
    return oss.str();
}

std::string SymbolInfo::to_string() const {
    std::ostringstream oss;
    oss << "SymbolInfo{name=" << name;
    if (!demangled_name.empty() && demangled_name != name) {
        oss << " (" << demangled_name << ")";
    }
    oss << ", addr=0x" << std::hex << address
        << std::dec << ", size=" << size
        << ", module=" << module_name
        << ", type=" << type
        << "}";
    return oss.str();
}

std::size_t SectionInfo::validate_addresses() const noexcept {
    std::size_t match_count = 0;
    for (const auto& entry : entries) {
        if (entry.address_matches) {
            ++match_count;
        }
    }
    return match_count;
}

} // namespace elf::got
