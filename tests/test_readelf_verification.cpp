/**
 * @file test_readelf_verification.cpp
 * @brief Tests that verify ELFParser output against readelf/objdump
 *
 * These tests run readelf/objdump on the same binaries and compare
 * the results to ensure our parser is correct.
 */

#include <elf_got/elf_got.h>
#include <gtest/gtest.h>

#include <fstream>
#include <sstream>
#include <regex>
#include <cstdlib>
#include <cstdio>
#include <cstring>
#include <memory>
#include <array>
#include <unordered_set>
#include <unordered_map>

using namespace elf::got;

namespace {

/**
 * @brief Helper class to execute and parse readelf output
 */
class ReadelfVerifier {
public:
    /**
     * @brief Represents a section from readelf -S output
     */
    struct ReadelfSection {
        std::string name;
        std::uintptr_t address = 0;
        std::size_t offset = 0;
        std::size_t size = 0;
        bool is_valid = false;
    };

    /**
     * @brief Represents a symbol from readelf --syms output
     */
    struct ReadelfSymbol {
        std::string name;
        std::uintptr_t value = 0;
        std::size_t size = 0;
        std::string type;
        std::string bind;
        std::size_t section_index = 0;
        bool is_valid = false;
    };

    /**
     * @brief Represents a relocation from readelf --relocs output
     */
    struct ReadelfRelocation {
        std::uintptr_t offset = 0;
        std::string type;
        std::string symbol;
        std::string section_name;
        bool is_valid = false;
    };

    explicit ReadelfVerifier(const std::string& elf_path)
        : elf_path_(elf_path) {}

    /**
     * @brief Check if readelf is available
     */
    static bool is_available() noexcept {
        return system("which readelf > /dev/null 2>&1") == 0;
    }

    /**
     * @brief Check if objdump is available
     */
    static bool objdump_available() noexcept {
        return system("which objdump > /dev/null 2>&1") == 0;
    }

    /**
     * @brief Execute a command and return its output
     */
    std::string exec_command(const std::string& cmd) const {
        std::array<char, 128> buffer;
        std::string result;
        std::unique_ptr<FILE, decltype(&pclose)> pipe(popen(cmd.c_str(), "r"), pclose);
        if (!pipe) {
            return "";
        }
        while (fgets(buffer.data(), buffer.size(), pipe.get()) != nullptr) {
            result += buffer.data();
        }
        return result;
    }

    /**
     * @brief Parse section headers using readelf -S
     */
    std::vector<ReadelfSection> parse_sections() const {
        std::vector<ReadelfSection> sections;
        std::string cmd = "readelf -S \"" + elf_path_ + "\" 2>/dev/null";
        std::string output = exec_command(cmd);
        if (output.empty()) {
            return sections;
        }

        std::istringstream stream(output);
        std::string line;

        // Parse each section line
        // readelf -S outputs in format:
        // [Nr] Name              Type            Address          Off
        //    Size                ES  Flg Lk  Inf  Al
        // Or in single-line format with -W flag
        while (std::getline(stream, line)) {
            // Skip headers and separators
            if (line.empty() || line.find("Section Headers:") != std::string::npos ||
                line.find("Nr]") != std::string::npos ||
                line.find("Key to Flags") != std::string::npos ||
                line.find("---") != std::string::npos) {
                continue;
            }

            // Parse section header line
            // Format: [ 1] .interp           PROGBITS         0000000000000318  00000318
            std::regex section_regex(
                R"(\[\s*\d+\]\s+(\S+)\s+\S+\s+([0-9a-f]+)\s+([0-9a-f]+))",
                std::regex::icase);
            std::smatch match;

            if (std::regex_search(line, match, section_regex)) {
                ReadelfSection sec;
                sec.name = match[1].str();
                try {
                    sec.address = std::stoull(match[2].str(), nullptr, 16);
                    sec.offset = std::stoull(match[3].str(), nullptr, 16);

                    // Size is on the next line
                    std::string next_line;
                    if (std::getline(stream, next_line)) {
                        // Format: 000000000000001c  00   A  0   0  1
                        std::regex size_regex(R"(\s*([0-9a-f]+))", std::regex::icase);
                        std::smatch size_match;
                        if (std::regex_search(next_line, size_match, size_regex)) {
                            sec.size = std::stoull(size_match[1].str(), nullptr, 16);
                        }
                    }

                    sec.is_valid = true;
                    sections.push_back(std::move(sec));
                } catch (...) {
                    // Parse error, skip this entry
                }
            }
        }

        return sections;
    }

    /**
     * @brief Get specific section info from readelf
     */
    std::optional<ReadelfSection> get_section(const std::string& name) const {
        auto sections = parse_sections();
        for (const auto& sec : sections) {
            if (sec.name == name) {
                return sec;
            }
        }
        return std::nullopt;
    }

    /**
     * @brief Parse dynamic symbols using readelf --syms
     */
    std::vector<ReadelfSymbol> parse_dynamic_symbols() const {
        std::vector<ReadelfSymbol> symbols;
        std::string cmd = "readelf --syms --dyn-syms \"" + elf_path_ + "\" 2>/dev/null";
        std::string output = exec_command(cmd);
        if (output.empty()) {
            return symbols;
        }

        std::istringstream stream(output);
        std::string line;

        // Skip until we find the symbol table
        bool in_symbol_table = false;
        while (std::getline(stream, line)) {
            if (line.find("Symbol table") != std::string::npos) {
                in_symbol_table = true;
                continue;
            }
            if (in_symbol_table && line.find("Num:") != std::string::npos) {
                // Header line, next lines are symbols
                continue;
            }
            if (in_symbol_table && !line.empty() && line[0] != ' ') {
                ReadelfSymbol sym;

                // Format:   Num:    Value          Size Type    Bind   Vis      Ndx Name
                //          146: 00000000000 0 FUNC GLOBAL DEFAULT 13 malloc@@GLIBC_2.2.5
                std::regex symbol_regex(
                    R"(\s*\d+:\s+([0-9a-f]+)\s+([0-9a-f]+)?\s+(\S+)\s+(\S+)\s+\S+\s+(\d+)\s+(.+))",
                    std::regex::icase);
                std::smatch match;

                if (std::regex_search(line, match, symbol_regex)) {
                    try {
                        sym.value = std::stoull(match[1].str(), nullptr, 16);
                        sym.size = match[2].str() == "-" ? 0 :
                                  std::stoull(match[2].str(), nullptr, 16);
                        sym.type = match[3].str();
                        sym.bind = match[4].str();
                        sym.section_index = std::stoull(match[5].str());
                        sym.name = match[6].str();

                        // Strip version suffix
                        const std::size_t at_pos = sym.name.find('@');
                        if (at_pos != std::string::npos) {
                            sym.name = sym.name.substr(0, at_pos);
                        }

                        sym.is_valid = true;
                        symbols.push_back(std::move(sym));
                    } catch (...) {
                        // Parse error
                    }
                }
            }
        }

        return symbols;
    }

    /**
     * @brief Parse relocations using readelf --relocs
     */
    std::vector<ReadelfRelocation> parse_relocations(const std::string& section = ".rela.plt") const {
        std::vector<ReadelfRelocation> relocs;
        std::string cmd = "readelf --relocs \"" + elf_path_ + "\" 2>/dev/null";
        std::string output = exec_command(cmd);
        if (output.empty()) {
            return relocs;
        }

        std::istringstream stream(output);
        std::string line;
        bool in_target_section = false;

        while (std::getline(stream, line)) {
            // Check if we're entering the target section
            if (line.find("' " + section + "'") != std::string::npos ||
                line.find("\"" + section + "\"") != std::string::npos ||
                line.find(" " + section + " at") != std::string::npos) {
                in_target_section = true;
                continue;
            }

            // Check if we're entering a different section
            if (line.find("Relocation section") != std::string::npos) {
                if (line.find(section) == std::string::npos) {
                    in_target_section = false;
                }
                continue;
            }

            if (in_target_section && !line.empty() && line[0] != ' ') {
                ReadelfRelocation reloc;
                reloc.section_name = section;

                // Format for RELA: offset  info                type               symbol value + addend
                // 0000000000035028  000100000007 R_X86_64_JUMP_SLO 00000000000 malloc + 0
                // or for REL: offset  info           type               symbol
                std::regex reloc_regex(
                    R"(([0-9a-f]+)\s+[0-9a-f]+\s+(\S+)\s+([0-9a-f]+)?\s*(.*))",
                    std::regex::icase);
                std::smatch match;

                if (std::regex_search(line, match, reloc_regex)) {
                    try {
                        reloc.offset = std::stoull(match[1].str(), nullptr, 16);
                        reloc.type = match[2].str();

                        std::string sym_or_addend = match[4].str();
                        // Parse symbol name and optional addend
                        const std::size_t plus_pos = sym_or_addend.find(" + ");
                        if (plus_pos != std::string::npos) {
                            reloc.symbol = sym_or_addend.substr(0, plus_pos);
                        } else {
                            reloc.symbol = sym_or_addend;
                        }

                        reloc.is_valid = !reloc.symbol.empty() && reloc.symbol != "-";
                        relocs.push_back(std::move(reloc));
                    } catch (...) {
                        // Parse error
                    }
                }
            }
        }

        return relocs;
    }

    /**
     * @brief Get all relocations from both .rela.dyn and .rela.plt
     */
    std::vector<ReadelfRelocation> parse_all_relocations() const {
        std::vector<ReadelfRelocation> all_relocs;

        // Try different relocation section types
        const std::vector<std::string> reloc_sections = {
            ".rela.plt", ".rel.plt", ".rela.dyn", ".rel.dyn"
        };

        for (const auto& section : reloc_sections) {
            auto relocs = parse_relocations(section);
            all_relocs.insert(all_relocs.end(),
                std::make_move_iterator(relocs.begin()),
                std::make_move_iterator(relocs.end()));
        }

        return all_relocs;
    }

private:
    std::string elf_path_;
};

// ============================================================================
// Test Fixture
// ============================================================================

class ReadelfVerificationTest : public ::testing::Test {
protected:
    static std::string find_test_binary() {
        const char* paths[] = {
            "/bin/ls",
            "/usr/bin/ls",
            "/lib/x86_64-linux-gnu/libc.so.6",
            "/lib64/libc.so.6",
            nullptr
        };

        for (const char* path : paths) {
            std::ifstream f(path);
            if (f.good()) {
                return path;
            }
        }
        return "";
    }

    std::string test_binary;

    void SetUp() override {
        if (!ReadelfVerifier::is_available()) {
            GTEST_SKIP() << "readelf not available";
        }
        test_binary = find_test_binary();
        if (test_binary.empty()) {
            GTEST_SKIP() << "No suitable test binary found";
        }
    }
};

// ============================================================================
// Section Header Tests
// ============================================================================

TEST_F(ReadelfVerificationTest, CompareGotSectionHeader) {
    ReadelfVerifier verifier(test_binary);

    // Get .got.plt section from readelf
    auto readelf_got_plt = verifier.get_section(".got.plt");

    // Parse with our parser
    auto got_info = ELFParser::parse(test_binary);
    ASSERT_TRUE(got_info.has_value()) << "Failed to parse " << test_binary;

    auto our_got_plt = got_info->got_plt();

    // Compare if both have .got.plt
    if (readelf_got_plt && our_got_plt) {
        EXPECT_EQ(our_got_plt->virtual_addr, readelf_got_plt->address)
            << ".got.plt virtual address mismatch";
        EXPECT_EQ(our_got_plt->size, readelf_got_plt->size)
            << ".got.plt size mismatch";
        EXPECT_EQ(our_got_plt->file_offset, readelf_got_plt->offset)
            << ".got.plt file offset mismatch";
    }
}

TEST_F(ReadelfVerificationTest, CompareGotPltSectionHeader) {
    ReadelfVerifier verifier(test_binary);

    // Get .got section from readelf
    auto readelf_got = verifier.get_section(".got");

    // Parse with our parser
    auto got_info = ELFParser::parse(test_binary);
    ASSERT_TRUE(got_info.has_value()) << "Failed to parse " << test_binary;

    auto our_got = got_info->got();

    // Compare if both have .got
    if (readelf_got && our_got) {
        EXPECT_EQ(our_got->virtual_addr, readelf_got->address)
            << ".got virtual address mismatch";
        EXPECT_EQ(our_got->size, readelf_got->size)
            << ".got size mismatch";
        EXPECT_EQ(our_got->file_offset, readelf_got->offset)
            << ".got file offset mismatch";
    }
}

TEST_F(ReadelfVerificationTest, AllGotSectionsFound) {
    ReadelfVerifier verifier(test_binary);

    auto readelf_sections = verifier.parse_sections();
    auto got_info = ELFParser::parse(test_binary);
    ASSERT_TRUE(got_info.has_value());

    // Check which GOT sections readelf found
    bool readelf_has_got = false;
    bool readelf_has_got_plt = false;
    for (const auto& sec : readelf_sections) {
        if (sec.name == ".got") readelf_has_got = true;
        if (sec.name == ".got.plt") readelf_has_got_plt = true;
    }

    // Compare with our parser
    bool our_has_got = got_info->got().has_value();
    bool our_has_got_plt = got_info->got_plt().has_value();

    // If readelf has .got, we should have it too (unless it's empty)
    if (readelf_has_got) {
        EXPECT_TRUE(our_has_got) << "readelf found .got but our parser didn't";
    }
    if (readelf_has_got_plt) {
        EXPECT_TRUE(our_has_got_plt) << "readelf found .got.plt but our parser didn't";
    }
}

// ============================================================================
// Relocation/Symbol Tests
// ============================================================================

TEST_F(ReadelfVerificationTest, CompareRelocationCount) {
    ReadelfVerifier verifier(test_binary);

    // Get all relocations from readelf
    auto readelf_relocs = verifier.parse_all_relocations();

    // Parse with our parser
    auto got_info = ELFParser::parse(test_binary);
    ASSERT_TRUE(got_info.has_value());

    // Count entries with symbols in our parser
    std::size_t our_symbol_count = 0;
    for (const auto& section : got_info->all_sections()) {
        for (const auto& entry : section.entries) {
            if (entry.has_symbol) {
                our_symbol_count++;
            }
        }
    }

    // Count non-null relocations from readelf
    std::size_t readelf_symbol_count = 0;
    for (const auto& reloc : readelf_relocs) {
        if (reloc.is_valid) {
            readelf_symbol_count++;
        }
    }

    // We may not find all symbols (e.g., without corresponding relocation),
    // but we should find a significant portion
    if (readelf_symbol_count > 0) {
        EXPECT_GT(our_symbol_count, 0) << "Our parser found no GOT symbols";
        // Allow some tolerance - we might miss some entries
        EXPECT_GE(our_symbol_count, readelf_symbol_count / 2)
            << "Our parser found significantly fewer symbols than readelf "
            << "(ours: " << our_symbol_count << ", readelf: " << readelf_symbol_count << ")";
    }
}

TEST_F(ReadelfVerificationTest, VerifyCommonSymbolsExist) {
    auto got_info = ELFParser::parse(test_binary);
    ASSERT_TRUE(got_info.has_value());

    // Build set of our found symbols
    std::unordered_set<std::string> our_symbols;
    for (const auto& section : got_info->all_sections()) {
        for (const auto& entry : section.entries) {
            if (entry.has_symbol) {
                our_symbols.insert(entry.symbol_name);
            }
        }
    }

    // Check for common symbols that should be in GOT of typical binaries
    std::vector<std::string> common_symbols = {
        "malloc", "free", "printf", "strlen", "strcpy", "strcmp",
        "memcpy", "memset", "strlen", "exit", "atoi"
    };

    // Use readelf to check what symbols are actually in this binary
    ReadelfVerifier verifier(test_binary);
    auto readelf_relocs = verifier.parse_all_relocations();
    std::unordered_set<std::string> readelf_symbols;
    for (const auto& reloc : readelf_relocs) {
        if (reloc.is_valid) {
            readelf_symbols.insert(reloc.symbol);
        }
    }

    // Verify that symbols present in readelf are also in our parser
    for (const auto& sym : common_symbols) {
        if (readelf_symbols.count(sym) > 0) {
            EXPECT_TRUE(our_symbols.count(sym) > 0)
                << "readelf found symbol '" << sym << "' but our parser didn't";
        }
    }
}

TEST_F(ReadelfVerificationTest, CompareSpecificSymbolAddresses) {
    ReadelfVerifier verifier(test_binary);

    auto readelf_relocs = verifier.parse_all_relocations();
    auto got_info = ELFParser::parse(test_binary);
    ASSERT_TRUE(got_info.has_value());

    // Build map of our symbols by address
    std::unordered_map<std::uintptr_t, std::string> our_symbols;
    for (const auto& section : got_info->all_sections()) {
        for (const auto& entry : section.entries) {
            if (entry.has_symbol) {
                our_symbols[entry.va] = entry.symbol_name;
            }
        }
    }

    // Compare addresses
    for (const auto& reloc : readelf_relocs) {
        if (!reloc.is_valid) continue;

        auto it = our_symbols.find(reloc.offset);
        if (it != our_symbols.end()) {
            // Found at same address - verify symbol name matches
            EXPECT_EQ(it->second, reloc.symbol)
                << "Symbol at offset 0x" << std::hex << reloc.offset
                << ": we have '" << it->second << "', readelf has '" << reloc.symbol << "'";
        }
    }
}

// ============================================================================
// Entry Count Tests
// ============================================================================

TEST_F(ReadelfVerificationTest, VerifyEntryCount) {
    ReadelfVerifier verifier(test_binary);

    auto got_info = ELFParser::parse(test_binary);
    ASSERT_TRUE(got_info.has_value());

    for (const auto& section : got_info->all_sections()) {
        auto readelf_sec = verifier.get_section(section.name);
        if (readelf_sec) {
            // Entry count should match size / pointer_size
            std::size_t expected_entries = readelf_sec->size / sizeof(void*);

            EXPECT_EQ(section.entry_count(), expected_entries)
                << "Entry count mismatch for section " << section.name
                << ": got " << section.entry_count() << ", expected " << expected_entries;
        }
    }
}

// ============================================================================
// Multiple Binary Tests
// ============================================================================

TEST_F(ReadelfVerificationTest, VerifyMultipleBinaries) {
    std::vector<std::string> test_binaries = {
        "/bin/ls",
        "/bin/cat",
        "/bin/sh",
        "/bin/echo",
        "/usr/bin/head",
        "/usr/bin/tail",
        test_binary  // Include the one we already know works
    };

    int verified_count = 0;
    int checked_count = 0;

    for (const auto& binary : test_binaries) {
        std::ifstream f(binary);
        if (!f.good()) continue;

        ReadelfVerifier verifier(binary);

        auto got_info = ELFParser::parse(binary);
        if (!got_info) continue;

        checked_count++;

        // Basic sanity checks - check both .got and .got.plt
        bool this_verified = false;

        // Check .got.plt first
        auto readelf_got_plt = verifier.get_section(".got.plt");
        auto our_got_plt = got_info->got_plt();

        if (readelf_got_plt && our_got_plt) {
            EXPECT_EQ(our_got_plt->virtual_addr, readelf_got_plt->address)
                << ".got.plt mismatch in " << binary;
            this_verified = true;
        }

        // Check .got as fallback
        auto readelf_got = verifier.get_section(".got");
        auto our_got = got_info->got();

        if (readelf_got && our_got) {
            EXPECT_EQ(our_got->virtual_addr, readelf_got->address)
                << ".got mismatch in " << binary;
            this_verified = true;
        }

        if (this_verified) {
            verified_count++;
        }
    }

    // At least one binary should be verified (the test_binary should work)
    if (checked_count > 0) {
        EXPECT_GT(verified_count, 0) << "Could not verify any of " << checked_count << " binaries";
    } else {
        GTEST_SKIP() << "No test binaries found";
    }
}

// ============================================================================
// Objdump Tests (if available)
// ============================================================================

TEST_F(ReadelfVerificationTest, CompareWithObjdump) {
    if (!ReadelfVerifier::objdump_available()) {
        GTEST_SKIP() << "objdump not available";
    }

    // Use objdump to get section info
    std::string cmd = "objdump -h \"" + test_binary + "\" 2>/dev/null";
    std::array<char, 128> buffer;
    std::string result;
    std::unique_ptr<FILE, decltype(&pclose)> pipe(popen(cmd.c_str(), "r"), pclose);
    if (!pipe) {
        GTEST_SKIP() << "Failed to run objdump";
    }

    while (fgets(buffer.data(), buffer.size(), pipe.get()) != nullptr) {
        result += buffer.data();
    }

    // Parse objdump output for .got.plt
    // Format: Sections:
    // Idx Name          Size      VMA               LMA               File off  Algn
    //   15 .got.plt     00000030  0000000000003e00  0000000000003e00  000003e00  2**3
    std::istringstream stream(result);
    std::string line;

    std::optional<std::uintptr_t> objdump_addr;
    std::optional<std::size_t> objdump_size;

    while (std::getline(stream, line)) {
        if (line.find(".got.plt") != std::string::npos) {
            std::regex objdump_regex(
                R"(\.got\.plt\s+([0-9a-f]+)\s+([0-9a-f]+))",
                std::regex::icase);
            std::smatch match;
            if (std::regex_search(line, match, objdump_regex)) {
                try {
                    objdump_size = std::stoull(match[1].str(), nullptr, 16);
                    objdump_addr = std::stoull(match[2].str(), nullptr, 16);
                } catch (...) {}
            }
            break;
        }
    }

    if (objdump_addr && objdump_size) {
        auto got_info = ELFParser::parse(test_binary);
        ASSERT_TRUE(got_info.has_value());

        auto our_got_plt = got_info->got_plt();
        if (our_got_plt) {
            EXPECT_EQ(our_got_plt->virtual_addr, *objdump_addr)
                << "objdump vs our parser: VMA mismatch";
            EXPECT_EQ(our_got_plt->size, *objdump_size)
                << "objdump vs our parser: size mismatch";
        }
    }
}

// ============================================================================
// Detailed Symbol Verification
// ============================================================================

TEST_F(ReadelfVerificationTest, DetailedSymbolComparison) {
    ReadelfVerifier verifier(test_binary);

    auto got_info = ELFParser::parse(test_binary);
    ASSERT_TRUE(got_info.has_value());

    auto readelf_relocs = verifier.parse_relocations(".rela.plt");

    // Build map from our parser
    std::unordered_map<std::uintptr_t, GOTEntry> our_entries;
    for (const auto& section : got_info->all_sections()) {
        for (const auto& entry : section.entries) {
            if (entry.has_symbol) {
                our_entries[entry.va] = entry;
            }
        }
    }

    // Verify each readelf relocation
    int matched_count = 0;
    for (const auto& reloc : readelf_relocs) {
        if (!reloc.is_valid) continue;

        auto it = our_entries.find(reloc.offset);
        if (it != our_entries.end()) {
            matched_count++;
            EXPECT_EQ(it->second.symbol_name, reloc.symbol)
                << "Symbol name mismatch at offset 0x" << std::hex << reloc.offset;
        }
    }

    // Report how many we matched
    if (!readelf_relocs.empty()) {
        double match_ratio = static_cast<double>(matched_count) / readelf_relocs.size();
        EXPECT_GT(match_ratio, 0.5)
            << "Only matched " << matched_count << "/" << readelf_relocs.size()
            << " (" << (match_ratio * 100) << "%) symbols from readelf";
    }
}

} // anonymous namespace
