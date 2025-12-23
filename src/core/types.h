#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>
#include <unordered_map>

namespace elf::got {

/**
 * @brief GOT entry with symbol and runtime information
 */
struct GOTEntry {
    std::size_t offset{0};                      ///< Offset within the GOT section
    std::uintptr_t va{0};                       ///< Virtual address from ELF
    std::string symbol_name;                    ///< Symbol name (empty if not found)
    std::size_t symbol_index{0};                ///< Symbol index in .dynsym
    bool has_symbol{false};                     ///< Whether symbol was found

    // Runtime values (populated by ProcessReader)
    std::optional<std::uintptr_t> runtime_value;///< Actual value in memory
    bool address_matches{false};                ///< Does calculated VA match actual?

    // Extended verification results
    std::string runtime_symbol_name;            ///< Symbol name at runtime address
    bool symbol_name_matches{false};            ///< Does symbol name match?
    std::optional<std::uintptr_t> expected_address;///< Calculated expected address
    bool address_is_hooked{false};              ///< Is address potentially hooked?

    [[nodiscard]] bool is_valid() const noexcept {
        return has_symbol;
    }

    [[nodiscard]] std::string to_string() const;
};

/**
 * @brief Memory region from /proc/pid/maps
 */
struct MemoryRegion {
    std::uintptr_t start{0};                    ///< Region start address
    std::uintptr_t end{0};                      ///< Region end address
    std::size_t offset{0};                      ///< File offset
    std::string perms;                          ///< Permissions (rwxp)
    std::string dev;                            ///< Device (major:minor)
    std::string inode;                          ///< Inode number
    std::string pathname;                       ///< Mapped file path (empty for anonymous)

    [[nodiscard]] bool contains(std::uintptr_t addr) const noexcept {
        return addr >= start && addr < end;
    }

    [[nodiscard]] std::size_t size() const noexcept {
        return end - start;
    }

    [[nodiscard]] bool is_readable() const noexcept {
        return perms.size() >= 1 && perms[0] == 'r';
    }

    [[nodiscard]] bool is_writable() const noexcept {
        return perms.size() >= 2 && perms[1] == 'w';
    }

    [[nodiscard]] bool is_executable() const noexcept {
        return perms.size() >= 3 && perms[2] == 'x';
    }

    [[nodiscard]] bool is_private() const noexcept {
        return perms.size() >= 4 && perms[3] == 'p';
    }

    [[nodiscard]] bool is_shared() const noexcept {
        return perms.size() >= 4 && perms[3] == 's';
    }

    [[nodiscard]] std::string to_string() const;
};

/**
 * @brief Symbol information
 */
struct SymbolInfo {
    std::string name;                           ///< Symbol name (mangled)
    std::string demangled_name;                 ///< Demangled name (if applicable)
    std::uintptr_t address{0};                  ///< Symbol address
    std::size_t size{0};                        ///< Symbol size
    std::string module_name;                    ///< Containing module/so name
    std::string type;                           ///< Symbol type (FUNC, OBJECT, etc.)

    [[nodiscard]] bool is_valid() const noexcept {
        return !name.empty();
    }

    [[nodiscard]] bool is_function() const noexcept {
        return type == "FUNC";
    }

    [[nodiscard]] std::string display_name() const noexcept {
        return demangled_name.empty() ? name : demangled_name;
    }

    [[nodiscard]] std::string to_string() const;
};

/**
 * @brief ELF section information with runtime data
 */
struct SectionInfo {
    std::string name;                           ///< Section name (.got, .got.plt, etc.)
    std::uintptr_t virtual_addr{0};             ///< Virtual address from ELF
    std::size_t file_offset{0};                 ///< Offset in file
    std::size_t size{0};                        ///< Section size in bytes
    std::uintptr_t base_addr{0};                ///< Load base address (runtime)
    std::vector<GOTEntry> entries;              ///< GOT entries with symbols

    [[nodiscard]] std::size_t entry_count() const noexcept {
        const std::size_t ptr_size = sizeof(void*);
        return ptr_size > 0 ? size / ptr_size : 0;
    }

    [[nodiscard]] std::uintptr_t runtime_address() const noexcept {
        return base_addr + virtual_addr;
    }

    [[nodiscard]] bool is_valid() const noexcept {
        return size > 0;
    }

    [[nodiscard]] bool has_symbols() const noexcept {
        for (const auto& entry : entries) {
            if (entry.has_symbol) return true;
        }
        return false;
    }

    /**
     * @brief Validate that runtime addresses match calculated addresses
     * @return Number of entries that match
     */
    [[nodiscard]] std::size_t validate_addresses() const noexcept;

    void add_entry(GOTEntry entry) noexcept {
        entries.push_back(std::move(entry));
    }

    void reserve_entries(std::size_t count) noexcept {
        entries.reserve(count);
    }
};

/**
 * @brief GOT (Global Offset Table) sections information
 */
class GOTInfo {
public:
    GOTInfo() = default;
    ~GOTInfo() = default;

    GOTInfo(const GOTInfo&) = default;
    GOTInfo& operator=(const GOTInfo&) = default;
    GOTInfo(GOTInfo&&) noexcept = default;
    GOTInfo& operator=(GOTInfo&&) noexcept = default;

    /**
     * @brief Set the .got section info
     */
    void set_got(SectionInfo got) noexcept {
        got_ = std::move(got);
    }

    /**
     * @brief Set the .got.plt section info
     */
    void set_got_plt(SectionInfo got_plt) noexcept {
        got_plt_ = std::move(got_plt);
    }

    /**
     * @brief Get the .got section (if present)
     */
    [[nodiscard]] const std::optional<SectionInfo>& got() const noexcept {
        return got_;
    }

    /**
     * @brief Get the .got.plt section (if present)
     */
    [[nodiscard]] const std::optional<SectionInfo>& got_plt() const noexcept {
        return got_plt_;
    }

    /**
     * @brief Check if any GOT sections were found
     */
    [[nodiscard]] bool has_got_sections() const noexcept {
        return got_.has_value() || got_plt_.has_value();
    }

    /**
     * @brief Get all sections as a vector
     */
    [[nodiscard]] std::vector<SectionInfo> all_sections() const {
        std::vector<SectionInfo> sections;
        sections.reserve(2);
        if (got_) sections.push_back(*got_);
        if (got_plt_) sections.push_back(*got_plt_);
        return sections;
    }

    /**
     * @brief Calculate runtime address for a section
     */
    [[nodiscard]] static void* calculate_runtime_address(
        void* base_address,
        const SectionInfo& section) noexcept {
        return static_cast<char*>(base_address) + section.virtual_addr;
    }

private:
    std::optional<SectionInfo> got_;
    std::optional<SectionInfo> got_plt_;
};

} // namespace elf::got
