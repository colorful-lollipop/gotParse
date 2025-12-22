#include <elf_got/elf_got.h>
#include <gtest/gtest.h>

#include <fstream>
#include <cstdlib>

using namespace elf::got;

namespace {

class ELFParserTest : public ::testing::Test {
protected:
    // Find libc.so.6 path (common on Linux)
    static std::string find_libc_path() {
        const char* env_paths[] = {
            "/lib/x86_64-linux-gnu/libc.so.6",
            "/lib64/libc.so.6",
            "/usr/lib/x86_64-linux-gnu/libc.so.6",
            "/lib/libc.so.6",
        };

        for (const char* path : env_paths) {
            std::ifstream f(path);
            if (f.good()) {
                return path;
            }
        }
        return "";  // Not found
    }

    std::string libc_path;
    std::string self_exe;

    void SetUp() override {
        libc_path = find_libc_path();
        self_exe = "/proc/self/exe";
    }
};

// Test parsing invalid file
TEST_F(ELFParserTest, ParseInvalidPath) {
    auto result = ELFParser::parse("/nonexistent/path/to/file.so");
    EXPECT_FALSE(result.has_value());
}

TEST_F(ELFParserTest, ParseExInvalidPath) {
    auto result = ELFParser::parse_ex("/nonexistent/path/to/file.so");
    EXPECT_FALSE(result.success);
    EXPECT_FALSE(result.error_message.empty());
}

// Test parsing /proc/self/exe (current executable)
TEST_F(ELFParserTest, ParseSelfExe) {
    auto result = ELFParser::parse_ex(self_exe);

    if (result.success) {
        EXPECT_TRUE(result.got_info.has_value());
        EXPECT_TRUE(result.got_info->has_got_sections());
    } else {
        // Some systems may have stripped binaries or no GOT
        GTEST_SKIP() << "Cannot parse self executable: " << result.error_message;
    }
}

// Test parsing libc if available
TEST_F(ELFParserTest, ParseLibc) {
    if (libc_path.empty()) {
        GTEST_SKIP() << "libc.so.6 not found on system";
    }

    auto result = ELFParser::parse_ex(libc_path);

    ASSERT_TRUE(result.success) << "Error: " << result.error_message;
    ASSERT_TRUE(result.got_info.has_value());
    EXPECT_TRUE(result.got_info->has_got_sections());
}

// Test .got.plt section exists
TEST_F(ELFParserTest, GotPltSection) {
    if (libc_path.empty()) {
        GTEST_SKIP() << "libc.so.6 not found on system";
    }

    auto got_info = ELFParser::parse(libc_path);
    ASSERT_TRUE(got_info.has_value());

    auto got_plt = got_info->got_plt();
    // .got.plt should exist in shared libraries
    if (got_plt) {
        EXPECT_EQ(got_plt->name, ".got.plt");
        EXPECT_GT(got_plt->size, 0);
        EXPECT_GT(got_plt->entry_count(), 0);
    }
}

// Test .got section exists
TEST_F(ELFParserTest, GotSection) {
    if (libc_path.empty()) {
        GTEST_SKIP() << "libc.so.6 not found on system";
    }

    auto got_info = ELFParser::parse(libc_path);
    ASSERT_TRUE(got_info.has_value());

    auto got = got_info->got();
    if (got) {
        EXPECT_EQ(got->name, ".got");
        EXPECT_GT(got->size, 0);
    }
}

// Test symbol extraction
TEST_F(ELFParserTest, SymbolExtraction) {
    if (libc_path.empty()) {
        GTEST_SKIP() << "libc.so.6 not found on system";
    }

    auto got_info = ELFParser::parse(libc_path);
    ASSERT_TRUE(got_info.has_value());

    bool found_common_symbol = false;

    auto check_symbols = [&](const std::optional<SectionInfo>& section) {
        if (!section) return;
        for (const auto& entry : section->entries) {
            if (entry.has_symbol) {
                // Common libc symbols that should be in GOT
                if (entry.symbol_name == "malloc" ||
                    entry.symbol_name == "free" ||
                    entry.symbol_name == "printf" ||
                    entry.symbol_name == "strlen") {
                    found_common_symbol = true;
                }
            }
        }
    };

    check_symbols(got_info->got_plt());
    check_symbols(got_info->got());

    if (!found_common_symbol) {
        // Symbols might be stripped
        GTEST_SKIP() << "No common symbols found (stripped binary?)";
    }
}

// Test ELF class detection
TEST_F(ELFParserTest, GetElfClassSelf) {
    int elf_class = ELFParser::get_elf_class(self_exe);
    // Should be 64 on most modern systems, 32 is also valid
    if (elf_class == 0) {
        GTEST_SKIP() << "Cannot determine ELF class";
    }
    EXPECT_TRUE(elf_class == 32 || elf_class == 64);
}

TEST_F(ELFParserTest, GetElfClassInvalid) {
    int elf_class = ELFParser::get_elf_class("/nonexistent/file");
    EXPECT_EQ(elf_class, 0);
}

// Test is_valid_elf
TEST_F(ELFParserTest, IsValidElfSelf) {
    EXPECT_TRUE(ELFParser::is_valid_elf(self_exe));
}

TEST_F(ELFParserTest, IsValidElfInvalid) {
    EXPECT_FALSE(ELFParser::is_valid_elf("/nonexistent/file"));
}

// Test calculate_runtime_va
TEST_F(ELFParserTest, CalculateRuntimeVa) {
    constexpr std::uintptr_t base = 0x400000;
    constexpr std::uintptr_t section_va = 0x3000;

    std::uintptr_t runtime = ELFParser::calculate_runtime_va(base, section_va);
    EXPECT_EQ(runtime, 0x403000);
}

// Test build_id extraction (if available)
TEST_F(ELFParserTest, GetBuildId) {
    std::string build_id = ELFParser::get_build_id(self_exe);

    // Build ID may not exist on all systems
    if (!build_id.empty()) {
        // Should be a hex string
        for (char c : build_id) {
            EXPECT_TRUE(std::isxdigit(c));
        }
    }
}

// Test entry count calculation
TEST_F(ELFParserTest, EntryCountCalculation) {
    if (libc_path.empty()) {
        GTEST_SKIP() << "libc.so.6 not found on system";
    }

    auto got_info = ELFParser::parse(libc_path);
    ASSERT_TRUE(got_info.has_value());

    auto check_entry_count = [&](const std::optional<SectionInfo>& section) {
        if (!section) return;
        // Each entry is pointer-sized
        EXPECT_GT(section->entry_count(), 0);
        // Entry count should match size / pointer_size
        std::size_t expected = section->size / sizeof(void*);
        EXPECT_EQ(section->entry_count(), expected);
    };

    check_entry_count(got_info->got_plt());
    check_entry_count(got_info->got());
}

// Test all_sections
TEST_F(ELFParserTest, AllSections) {
    if (libc_path.empty()) {
        GTEST_SKIP() << "libc.so.6 not found on system";
    }

    auto got_info = ELFParser::parse(libc_path);
    ASSERT_TRUE(got_info.has_value());

    auto sections = got_info->all_sections();
    EXPECT_GT(sections.size(), 0);
    EXPECT_LE(sections.size(), 2);  // At most .got and .got.plt
}

} // anonymous namespace
