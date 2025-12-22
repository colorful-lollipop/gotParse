#include "elf_parser.h"

// ELFIO - ELF file parsing library
#include <elfio/elfio.hpp>
#include <elfio/elf_types.hpp>

#include <algorithm>
#include <cstring>
#include <map>

namespace elf::got {

namespace {

// Raw ELF64 symbol structure (for direct access)
struct RawElf64Sym {
    std::uint32_t st_name;
    std::uint8_t  st_info;
    std::uint8_t  st_other;
    std::uint16_t st_shndx;
    std::uint64_t st_value;
    std::uint64_t st_size;
};

// Raw ELF32 symbol structure
struct RawElf32Sym {
    std::uint32_t st_name;
    std::uint32_t st_value;
    std::uint32_t st_size;
    std::uint8_t  st_info;
    std::uint8_t  st_other;
    std::uint16_t st_shndx;
};

// Map: GOT address -> {symbol name, symbol index}
using SymbolMap = std::map<std::size_t, std::pair<std::string, std::size_t>>;

/**
 * @brief Get symbol name by index from .dynsym and .dynstr sections
 * @param dynsym_section Dynamic symbol section
 * @param dynstr_section Dynamic string section
 * @param symbol_index Index of symbol in .dynsym
 * @return Symbol name (empty on error)
 */
[[nodiscard]] std::string get_symbol_name(
    ELFIO::section* dynsym_section,
    ELFIO::section* dynstr_section,
    std::size_t symbol_index) noexcept {
    if (!dynsym_section || !dynstr_section) {
        return "";
    }

    const char* strtab = static_cast<const char*>(dynstr_section->get_data());
    const char* sym_data = dynsym_section->get_data();

    if (!strtab || !sym_data) {
        return "";
    }

    // Calculate entry size based on ELF class
    const std::size_t entry_size = (dynsym_section->get_entry_size() > 0)
        ? dynsym_section->get_entry_size()
        : sizeof(RawElf64Sym);

    const std::size_t sym_offset = symbol_index * entry_size;
    const std::size_t sym_section_size = dynsym_section->get_size();

    // Bounds check
    if (sym_offset + sizeof(std::uint32_t) > sym_section_size) {
        return "";
    }

    // Read st_name offset
    const std::uint32_t st_name = *reinterpret_cast<const std::uint32_t*>(
        sym_data + sym_offset);

    if (st_name == 0 || st_name >= dynstr_section->get_size()) {
        return "";
    }

    std::string name = strtab + st_name;

    // Strip version suffix (e.g., "func@GLIBC_2.2.5" -> "func")
    const std::size_t at_pos = name.find('@');
    if (at_pos != std::string::npos) {
        name = name.substr(0, at_pos);
    }

    return name;
}

/**
 * @brief Build a map from GOT addresses to symbol names from relocation entries
 * @param reader ELFIO reader instance
 * @param rel_section Relocation section (.rela.dyn, .rela.plt, etc.)
 * @param dynsym_section Dynamic symbol section
 * @return Map of GOT addresses to symbol information
 */
[[nodiscard]] SymbolMap build_symbol_map(
    ELFIO::elfio& reader,
    ELFIO::section* rel_section,
    ELFIO::section* dynsym_section) noexcept {
    SymbolMap symbol_map;

    if (!rel_section || !dynsym_section) {
        return symbol_map;
    }

    // Get string table section
    ELFIO::section* dynstr_section = reader.sections[".dynstr"];
    if (!dynstr_section) {
        return symbol_map;
    }

    // Process relocation entries based on type
    const ELFIO::Elf_Half rel_type = rel_section->get_type();

    if (rel_type == ELFIO::SHT_RELA) {
        ELFIO::relocation_section_accessor rela(reader, rel_section);

        for (ELFIO::Elf_Xword i = 0; i < rela.get_entries_num(); ++i) {
            ELFIO::Elf64_Addr offset = 0;
            ELFIO::Elf_Word symbol = 0;
            ELFIO::Elf_Word type = 0;
            ELFIO::Elf_Sxword addend = 0;
            rela.get_entry(i, offset, symbol, type, addend);

            // Skip relocations without symbols (e.g., R_X86_64_RELATIVE)
            if (symbol == 0) {
                continue;
            }

            std::string symbol_name = get_symbol_name(
                dynsym_section, dynstr_section, symbol);
            if (!symbol_name.empty()) {
                symbol_map[offset] = {std::move(symbol_name), symbol};
            }
        }
    } else if (rel_type == ELFIO::SHT_REL) {
        ELFIO::relocation_section_accessor rel(reader, rel_section);

        for (ELFIO::Elf_Xword i = 0; i < rel.get_entries_num(); ++i) {
            ELFIO::Elf64_Addr offset = 0;
            ELFIO::Elf_Word symbol = 0;
            ELFIO::Elf_Word type = 0;
            ELFIO::Elf_Sxword addend = 0;
            rel.get_entry(i, offset, symbol, type, addend);

            // Skip relocations without symbols
            if (symbol == 0) {
                continue;
            }

            std::string symbol_name = get_symbol_name(
                dynsym_section, dynstr_section, symbol);
            if (!symbol_name.empty()) {
                symbol_map[offset] = {std::move(symbol_name), symbol};
            }
        }
    }

    return symbol_map;
}

/**
 * @brief Find symbols for GOT entries using relocation and symbol tables
 * @param reader ELFIO reader instance
 * @param section_info SectionInfo to populate
 * @param symbol_map Map of GOT addresses to symbols
 */
void populate_got_symbols(
    ELFIO::elfio& reader,
    SectionInfo& section_info,
    const SymbolMap& symbol_map) noexcept {
    // Get pointer size (4 or 8 bytes depending on ELF class)
    const std::size_t entry_size =
        (reader.get_class() == ELFIO::ELFCLASS64) ? 8 : 4;

    const std::size_t num_entries = section_info.size / entry_size;
    section_info.reserve_entries(num_entries);

    // Create entries for each GOT slot
    for (std::size_t i = 0; i < num_entries; ++i) {
        GOTEntry entry;
        entry.offset = i * entry_size;
        entry.va = section_info.virtual_addr + entry.offset;

        // Look up symbol for this address
        const auto it = symbol_map.find(entry.va);
        if (it != symbol_map.end()) {
            entry.symbol_name = it->second.first;
            entry.symbol_index = it->second.second;
            entry.has_symbol = true;
        }

        section_info.add_entry(std::move(entry));
    }
}

/**
 * @brief Parse a single GOT section from ELF
 * @param reader ELFIO reader instance
 * @param section_name Name of section to parse (.got or .got.plt)
 * @param rela_map Map from RELA relocations
 * @param rel_map Map from REL relocations
 * @param dynsym_section Dynamic symbol section
 * @return Parsed SectionInfo or empty optional
 */
[[nodiscard]] std::optional<SectionInfo> parse_got_section(
    ELFIO::elfio& reader,
    const std::string& section_name,
    const SymbolMap& rela_map,
    const SymbolMap& rel_map,
    ELFIO::section* dynsym_section) noexcept {
    ELFIO::section* sec = reader.sections[section_name];
    if (!sec) {
        return std::nullopt;
    }

    SectionInfo info;
    info.name = section_name;
    info.virtual_addr = sec->get_address();
    info.file_offset = sec->get_offset();
    info.size = sec->get_size();

    // Use the appropriate relocation map
    const SymbolMap& combined_map = rela_map.empty() ? rel_map : rela_map;
    populate_got_symbols(reader, info, combined_map);

    return info;
}

} // anonymous namespace

std::optional<GOTInfo> ELFParser::parse(const std::string& elf_path) noexcept {
    ParseResult result = parse_ex(elf_path);
    return result.success ? std::move(result.got_info) : std::nullopt;
}

ELFParser::ParseResult ELFParser::parse_ex(const std::string& elf_path) noexcept {
    ParseResult result;
    result.success = false;

    // Create ELFIO reader
    ELFIO::elfio reader;

    // Load ELF file
    if (!reader.load(elf_path)) {
        result.error_message = "Failed to load ELF file: " + elf_path;
        return result;
    }

    // Verify it's an ELF file
    if (reader.get_class() == ELFIO::ELFCLASSNONE) {
        result.error_message = "Not a valid ELF file: " + elf_path;
        return result;
    }

    // Find dynamic symbol section
    ELFIO::section* dynsym_section = reader.sections[".dynsym"];
    if (!dynsym_section) {
        dynsym_section = reader.sections[".symtab"];
    }

    // Build symbol maps from different relocation sections
    const SymbolMap rela_dyn_map =
        build_symbol_map(reader, reader.sections[".rela.dyn"], dynsym_section);
    const SymbolMap rel_dyn_map =
        build_symbol_map(reader, reader.sections[".rel.dyn"], dynsym_section);
    const SymbolMap rela_plt_map =
        build_symbol_map(reader, reader.sections[".rela.plt"], dynsym_section);
    const SymbolMap rel_plt_map =
        build_symbol_map(reader, reader.sections[".rel.plt"], dynsym_section);

    GOTInfo got_info;

    // Parse .got.plt section
    if (auto got_plt = parse_got_section(reader, ".got.plt",
            rela_plt_map, rel_plt_map, dynsym_section)) {
        got_info.set_got_plt(std::move(*got_plt));
    }

    // Parse .got section
    if (auto got = parse_got_section(reader, ".got",
            rela_dyn_map, rel_dyn_map, dynsym_section)) {
        got_info.set_got(std::move(*got));
    }

    // Check if at least one GOT section was found
    if (!got_info.has_got_sections()) {
        result.error_message = "No GOT sections found in: " + elf_path;
        return result;
    }

    result.success = true;
    result.got_info = std::move(got_info);
    return result;
}

int ELFParser::get_elf_class(const std::string& elf_path) noexcept {
    ELFIO::elfio reader;
    if (!reader.load(elf_path)) {
        return 0;
    }

    switch (reader.get_class()) {
        case ELFIO::ELFCLASS32: return 32;
        case ELFIO::ELFCLASS64: return 64;
        default: return 0;
    }
}

bool ELFParser::is_valid_elf(const std::string& elf_path) noexcept {
    ELFIO::elfio reader;
    if (!reader.load(elf_path)) {
        return false;
    }
    return reader.get_class() != ELFIO::ELFCLASSNONE;
}

std::string ELFParser::get_build_id(const std::string& elf_path) noexcept {
    ELFIO::elfio reader;
    if (!reader.load(elf_path)) {
        return "";
    }

    // Try .note.gnu.build-id section
    ELFIO::section* build_id_section = reader.sections[".note.gnu.build-id"];
    if (!build_id_section) {
        return "";
    }

    const ELFIO::Elf_Xword section_size = build_id_section->get_size();
    if (section_size < 16) {  // Minimum size for build-id note
        return "";
    }

    const char* data = build_id_section->get_data();
    if (!data) {
        return "";
    }

    // Parse note entry: namesz (4), descsz (4), type (4), name, desc
    // For build-id: name is "GNU\0", desc is the build ID bytes
    const std::uint32_t* data32 = reinterpret_cast<const std::uint32_t*>(data);

    std::uint32_t namesz = data32[0];
    std::uint32_t descsz = data32[1];

    // Validate sizes
    if (namesz != 4 || descsz == 0 || descsz > 64) {
        return "";
    }

    // Build ID data starts after header (12 bytes) + name (4 bytes, aligned)
    const std::size_t offset = 12 + ((namesz + 3) & ~std::size_t{3});
    if (offset + descsz > section_size) {
        return "";
    }

    // Convert to hex string
    const unsigned char* build_id =
        reinterpret_cast<const unsigned char*>(data + offset);

    std::string result;
    result.reserve(descsz * 2);
    for (std::uint32_t i = 0; i < descsz; ++i) {
        char buf[3];
        snprintf(buf, sizeof(buf), "%02x", build_id[i]);
        result += buf;
    }

    return result;
}

} // namespace elf::got
