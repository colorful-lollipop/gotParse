#include <elf_got/elf_got.h>
#include <gtest/gtest.h>

#include <fstream>
#include <cstdlib>

using namespace elf::got;

namespace {

class MapsParserTest : public ::testing::Test {
protected:
    void SetUp() override {
        // Check if /proc/self/maps is accessible
        std::ifstream f("/proc/self/maps");
        if (!f.good()) {
            GTEST_SKIP() << "/proc/self/maps not accessible";
        }
    }
};

// Test parse self maps
TEST_F(MapsParserTest, ParseSelf) {
    auto result = MapsParser::parse(0);  // 0 = self
    ASSERT_TRUE(result.has_value());
    EXPECT_TRUE(result->success);
    EXPECT_FALSE(result->regions.empty());
}

TEST_F(MapsParserTest, ParseExSelf) {
    auto result = MapsParser::parse_ex(0);
    EXPECT_TRUE(result.success);
    EXPECT_FALSE(result.regions.empty());
    EXPECT_TRUE(result.error_message.empty());
}

// Test parse_line with valid input
TEST_F(MapsParserTest, ParseLineValid) {
    std::string line = "7f1234567000-7f1234568000 rw-p 00007000 08:01 1234567 /lib/libc.so.6";
    auto region = MapsParser::parse_line(line);

    ASSERT_TRUE(region.has_value());
    EXPECT_EQ(region->start, 0x7f1234567000);
    EXPECT_EQ(region->end, 0x7f1234568000);
    EXPECT_EQ(region->perms, "rw-p");
    EXPECT_EQ(region->offset, 0x7000);
    EXPECT_EQ(region->dev, "08:01");
    EXPECT_EQ(region->inode, "1234567");
    EXPECT_EQ(region->pathname, "/lib/libc.so.6");
}

// Test parse_line with anonymous region
TEST_F(MapsParserTest, ParseLineAnonymous) {
    std::string line = "7f1234567000-7f1234568000 rw-p 00000000 00:00 0 [heap]";
    auto region = MapsParser::parse_line(line);

    ASSERT_TRUE(region.has_value());
    EXPECT_EQ(region->pathname, "[heap]");
}

// Test parse_line with special regions
TEST_F(MapsParserTest, ParseLineSpecialRegions) {
    struct TestCase {
        std::string line;
        std::string expected_path;
    };

    std::vector<TestCase> cases = {
        {"7fff12345000-7fff12346000 rw-p 00000000 00:00 0 [stack]", "[stack]"},
        {"7fff12345000-7fff12346000 r--p 00000000 00:00 0 [vvar]", "[vvar]"},
        {"7fff12345000-7fff12346000 r-xp 00000000 00:00 0 [vdso]", "[vdso]"},
        {"7fff12345000-7fff12346000 r-xp 00000000 00:00 0 [vsyscall]", "[vsyscall]"},
    };

    for (const auto& tc : cases) {
        auto region = MapsParser::parse_line(tc.line);
        ASSERT_TRUE(region.has_value()) << "Failed to parse: " << tc.line;
        EXPECT_EQ(region->pathname, tc.expected_path);
    }
}

// Test parse_line with empty line
TEST_F(MapsParserTest, ParseLineEmpty) {
    auto region = MapsParser::parse_line("");
    EXPECT_FALSE(region.has_value());
}

// Test parse_line with invalid format
TEST_F(MapsParserTest, ParseLineInvalid) {
    auto region = MapsParser::parse_line("invalid line format");
    EXPECT_FALSE(region.has_value());
}

// Test parse_line with different permission strings
TEST_F(MapsParserTest, ParseLinePermissions) {
    struct TestCase {
        std::string perms;
        bool readable;
        bool writable;
        bool executable;
        bool private_map;
    };

    std::vector<TestCase> cases = {
        {"r--p", true, false, false, true},
        {"r-xp", true, false, true, true},
        {"rw-p", true, true, false, true},
        {"rwxp", true, true, true, true},
        {"rw-s", true, true, false, false},  // shared
        {"r-xs", true, false, true, false},  // shared
    };

    for (const auto& tc : cases) {
        std::string line = "7f1234567000-7f1234568000 " + tc.perms +
                          " 00000000 08:01 1234567 /lib/test.so";
        auto region = MapsParser::parse_line(line);
        ASSERT_TRUE(region.has_value());

        EXPECT_EQ(region->is_readable(), tc.readable) << "For perms: " << tc.perms;
        EXPECT_EQ(region->is_writable(), tc.writable) << "For perms: " << tc.perms;
        EXPECT_EQ(region->is_executable(), tc.executable) << "For perms: " << tc.perms;
        EXPECT_EQ(region->is_private(), tc.private_map) << "For perms: " << tc.perms;
        EXPECT_EQ(region->is_shared(), !tc.private_map) << "For perms: " << tc.perms;
    }
}

// Test get_maps_path
TEST_F(MapsParserTest, GetMapsPath) {
    EXPECT_EQ(MapsParser::get_maps_path(0), "/proc/self/maps");
    EXPECT_EQ(MapsParser::get_maps_path(1234), "/proc/1234/maps");
}

// Test find_region
TEST_F(MapsParserTest, FindRegion) {
    auto result = MapsParser::parse(0);
    ASSERT_TRUE(result.has_value());

    // Find a region that should exist (stack or heap is common)
    for (const auto& region : result->regions) {
        auto found_region = MapsParser::find_region(result->regions, region.start);
        ASSERT_TRUE(found_region.has_value());
        EXPECT_EQ(found_region->start, region.start);
    }

    // Try to find an address that shouldn't exist
    auto not_found = MapsParser::find_region(result->regions, 0x1);  // Very low address
    // Kernel memory at 0x1 probably not mapped
    // Might still find something on some systems, so just check function works
}

// Test find_module_base
TEST_F(MapsParserTest, FindModuleBase) {
    auto result = MapsParser::parse(0);
    ASSERT_TRUE(result.has_value());

    // Look for libc
    auto libc_base = MapsParser::find_module_base(result->regions, "libc.so.6");
    if (libc_base.has_value()) {
        EXPECT_GT(*libc_base, 0);
    }

    // Try with full path (partial match)
    auto libc_base2 = MapsParser::find_module_base(result->regions, "/lib/libc.so");
    if (libc_base2.has_value()) {
        EXPECT_GT(*libc_base2, 0);
    }

    // Try non-existent module
    auto not_found = MapsParser::find_module_base(result->regions, "nonexistent.so");
    EXPECT_FALSE(not_found.has_value());
}

// Test find_module_regions
TEST_F(MapsParserTest, FindModuleRegions) {
    auto result = MapsParser::parse(0);
    ASSERT_TRUE(result.has_value());

    // Find regions for libc
    auto libc_regions = MapsParser::find_module_regions(result->regions, "libc.so.6");
    if (!libc_regions.empty()) {
        EXPECT_GT(libc_regions.size(), 0);
        for (const auto& region : libc_regions) {
            EXPECT_NE(region.pathname.find("libc"), std::string::npos);
        }
    }
}

// Test module_bases extraction
TEST_F(MapsParserTest, ModuleBases) {
    auto result = MapsParser::parse(0);
    ASSERT_TRUE(result.has_value());

    EXPECT_FALSE(result->module_bases.empty());

    // At least one module should have been found
    for (const auto& [path, base] : result->module_bases) {
        if (path.find("libc") != std::string::npos) {
            EXPECT_GT(base, 0);
        }
    }

    // libc might not be found on all systems
}

// Test ParseResult::find_base
TEST_F(MapsParserTest, ParseResultFindBase) {
    auto result = MapsParser::parse(0);
    ASSERT_TRUE(result.has_value());

    // Test the convenience method
    for (const auto& [path, base] : result->module_bases) {
        auto found_base = result->find_base(path);
        ASSERT_TRUE(found_base.has_value());
        EXPECT_EQ(*found_base, base);
    }

    auto not_found = result->find_base("/nonexistent/path.so");
    EXPECT_FALSE(not_found.has_value());
}

// Test MemoryRegion size calculation
TEST_F(MapsParserTest, MemoryRegionSize) {
    auto result = MapsParser::parse(0);
    ASSERT_TRUE(result.has_value());

    for (const auto& region : result->regions) {
        EXPECT_GT(region.size(), 0);
        EXPECT_EQ(region.size(), region.end - region.start);
    }
}

// Test that regions are sorted
TEST_F(MapsParserTest, RegionsSorted) {
    auto result = MapsParser::parse(0);
    ASSERT_TRUE(result.has_value());

    const auto& regions = result->regions;
    for (std::size_t i = 1; i < regions.size(); ++i) {
        EXPECT_GE(regions[i].start, regions[i-1].start);
    }
}

} // anonymous namespace
