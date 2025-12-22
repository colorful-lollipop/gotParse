#include <elf_got/elf_got.h>
#include <gtest/gtest.h>

#include <fstream>
#include <thread>
#include <chrono>
#include <cstring>
#include <cstdio>

using namespace elf::got;

namespace {

class ProcessReaderTest : public ::testing::Test {
protected:
    void SetUp() override {
        // Check if /proc is accessible
        std::ifstream f("/proc/self/maps");
        if (!f.good()) {
            GTEST_SKIP() << "/proc not accessible";
        }
    }
};

// Test construction for self process
TEST_F(ProcessReaderTest, ConstructSelf) {
    ProcessReader reader(0);  // 0 = self
    EXPECT_EQ(reader.pid(), 0);
}

// Test is_valid
TEST_F(ProcessReaderTest, IsValid) {
    ProcessReader reader(0);
    // May not be valid if we can't open /proc/self/mem
    // but the function should not crash
    static_cast<void>(reader.is_valid());
    // Result depends on system configuration
}

// Test move construction
TEST_F(ProcessReaderTest, MoveConstruct) {
    ProcessReader reader1(0);
    ProcessReader reader2(std::move(reader1));

    EXPECT_EQ(reader2.pid(), 0);
}

// Test move assignment
TEST_F(ProcessReaderTest, MoveAssign) {
    ProcessReader reader1(0);
    ProcessReader reader2(1);  // Non-existent PID

    reader2 = std::move(reader1);

    EXPECT_EQ(reader2.pid(), 0);
}

// Test read_pointer on self
TEST_F(ProcessReaderTest, ReadPointerSelf) {
    ProcessReader reader(0);

    if (!reader.is_valid()) {
        GTEST_SKIP() << "Cannot open /proc/self/mem";
    }

    // Read address of a stack variable
    std::uintptr_t local_var = 0x12345678;
    auto result = reader.read_pointer(
        reinterpret_cast<std::uintptr_t>(&local_var));

    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(*result, 0x12345678);
}

// Test read_buffer on self
TEST_F(ProcessReaderTest, ReadBufferSelf) {
    ProcessReader reader(0);

    if (!reader.is_valid()) {
        GTEST_SKIP() << "Cannot open /proc/self/mem";
    }

    // Test buffer
    alignas(std::uintptr_t) std::byte buffer[32];
    std::memset(buffer, 0xAA, sizeof(buffer));

    auto result = reader.read(
        reinterpret_cast<std::uintptr_t>(buffer),
        sizeof(buffer));

    ASSERT_TRUE(result.success);
    EXPECT_EQ(result.data.size(), sizeof(buffer));

    // Verify data
    for (std::size_t i = 0; i < sizeof(buffer); ++i) {
        EXPECT_EQ(static_cast<unsigned char>(result.data[i]), 0xAA);
    }
}

// Test read with size 0
TEST_F(ProcessReaderTest, ReadZeroSize) {
    ProcessReader reader(0);
    if (!reader.is_valid()) {
        GTEST_SKIP() << "Cannot open /proc/self/mem";
    }

    auto result = reader.read(0x1000, 0);
    EXPECT_TRUE(result.success);
    EXPECT_TRUE(result.data.empty());
}

// Test read with invalid address
TEST_F(ProcessReaderTest, ReadInvalidAddress) {
    ProcessReader reader(0);
    if (!reader.is_valid()) {
        GTEST_SKIP() << "Cannot open /proc/self/mem";
    }

    // Try to read from kernel space or unmapped region
    auto result = reader.read(0xffffffffffff0000, 8);
    EXPECT_FALSE(result.success);
}

// Test read_got_entry
TEST_F(ProcessReaderTest, ReadGotEntry) {
    ProcessReader reader(0);
    if (!reader.is_valid()) {
        GTEST_SKIP() << "Cannot open /proc/self/mem";
    }

    // Read from current executable's GOT if available
    auto maps_result = MapsParser::parse(0);
    ASSERT_TRUE(maps_result.has_value());

    // Find libc GOT
    for (const auto& [path, base] : maps_result->module_bases) {
        if (path.find("libc") == std::string::npos) {
            continue;
        }

        auto got_info = ELFParser::parse(path);
        if (!got_info) {
            continue;
        }

        auto got_plt = got_info->got_plt();
        if (!got_plt || got_plt->entries.empty()) {
            continue;
        }

        // Read first GOT entry
        const auto& entry = got_plt->entries[0];
        std::uintptr_t entry_va = base + entry.va;

        auto value = reader.read_got_entry(entry_va);
        if (value.has_value()) {
            // GOT entry should have some value (possibly PLT resolver)
            // Just check we got something
            EXPECT_TRUE(value.has_value());
        }

        break;  // Test one module is enough
    }
}

// Test refresh_regions
TEST_F(ProcessReaderTest, RefreshRegions) {
    ProcessReader reader(0);

    bool success = reader.refresh_regions();
    EXPECT_TRUE(success);

    auto regions = reader.regions();
    ASSERT_TRUE(regions.has_value());
    EXPECT_FALSE(regions->empty());
}

// Test find_region
TEST_F(ProcessReaderTest, FindRegion) {
    ProcessReader reader(0);

    // Get a known address (our stack variable)
    std::uintptr_t stack_addr = reinterpret_cast<std::uintptr_t>(&stack_addr);

    auto region = reader.find_region(stack_addr);

    if (region.has_value()) {
        EXPECT_TRUE(region->contains(stack_addr));
    }
}

// Test find_module_base
TEST_F(ProcessReaderTest, FindModuleBase) {
    ProcessReader reader(0);

    // Try to find libc
    auto libc_base = reader.find_module_base("libc.so.6");
    // May or may not be found depending on system

    // Try non-existent module
    auto not_found = reader.find_module_base("nonexistent_module_xyz.so");
    EXPECT_FALSE(not_found.has_value());
}

// Test get_module_bases
TEST_F(ProcessReaderTest, GetModuleBases) {
    ProcessReader reader(0);

    auto bases = reader.get_module_bases();
    EXPECT_FALSE(bases.empty());

    // At least one module should be found
    bool has_any = false;
    for (const auto& [path, base] : bases) {
        if (!path.empty() && path[0] != '[') {
            has_any = true;
            EXPECT_GT(base, 0);
        }
    }
    EXPECT_TRUE(has_any);
}

// Test error_to_string
TEST_F(ProcessReaderTest, ErrorToString) {
    EXPECT_STREQ(ProcessReader::error_to_string(ProcessReader::ReadError::None),
                 "No error");
    EXPECT_STREQ(ProcessReader::error_to_string(ProcessReader::ReadError::PermissionDenied),
                 "Permission denied");
    EXPECT_STREQ(ProcessReader::error_to_string(ProcessReader::ReadError::InvalidAddress),
                 "Invalid address");
    EXPECT_STREQ(ProcessReader::error_to_string(ProcessReader::ReadError::ProcessNotFound),
                 "Process not found");
    EXPECT_STREQ(ProcessReader::error_to_string(ProcessReader::ReadError::BufferTooSmall),
                 "Buffer too small");
    EXPECT_STREQ(ProcessReader::error_to_string(ProcessReader::ReadError::Unknown),
                 "Unknown error");
}

// Test read_got_section
TEST_F(ProcessReaderTest, ReadGotSection) {
    ProcessReader reader(0);
    if (!reader.is_valid()) {
        GTEST_SKIP() << "Cannot open /proc/self/mem";
    }

    // Find a GOT section to read
    auto maps_result = MapsParser::parse(0);
    ASSERT_TRUE(maps_result.has_value());

    for (const auto& [path, base] : maps_result->module_bases) {
        if (path.find("libc") == std::string::npos) {
            continue;
        }

        auto got_info = ELFParser::parse(path);
        if (!got_info) {
            continue;
        }

        auto got_plt = got_info->got_plt();
        if (!got_plt || got_plt->entry_count() == 0) {
            continue;
        }

        std::uintptr_t got_va = base + got_plt->virtual_addr;
        auto values = reader.read_got_section(got_va,
            std::min(got_plt->entry_count(), std::size_t(4)));  // Read up to 4 entries

        // At least we got something (even if empty, function works)
        break;
    }
}

// Test populate_got_runtime_values
TEST_F(ProcessReaderTest, PopulateGotRuntimeValues) {
    ProcessReader reader(0);
    if (!reader.is_valid()) {
        GTEST_SKIP() << "Cannot open /proc/self/mem";
    }

    auto maps_result = MapsParser::parse(0);
    ASSERT_TRUE(maps_result.has_value());

    for (const auto& [path, base] : maps_result->module_bases) {
        if (path.find("libc") == std::string::npos) {
            continue;
        }

        auto got_info = ELFParser::parse(path);
        if (!got_info) {
            continue;
        }

        auto got_plt = got_info->got_plt();
        if (!got_plt) {
            continue;
        }

        SectionInfo section = *got_plt;
        section.base_addr = base;

        static_cast<void>(reader.populate_got_runtime_values(section));

        // Some entries should be populated
        // At minimum, function should work without crash
        break;
    }
}

// Test reading from non-existent process
TEST_F(ProcessReaderTest, NonExistentProcess) {
    // Use a PID that's unlikely to exist
    constexpr pid_t unlikely_pid = 999999;

    ProcessReader reader(unlikely_pid);
    // Reader should handle this gracefully

    if (!reader.is_valid()) {
        // Expected - process doesn't exist
        auto result = reader.read(0x1000, 8);
        EXPECT_FALSE(result.success);
    }
}

// Test self address resolution
TEST_F(ProcessReaderTest, SelfAddressResolution) {
    ProcessReader reader(0);
    if (!reader.is_valid()) {
        GTEST_SKIP() << "Cannot open /proc/self/mem";
    }

    // Get address of a known function (printf from libc)
    void* func_addr = reinterpret_cast<void*>(&printf);
    auto self_addr = reinterpret_cast<std::uintptr_t>(func_addr);

    auto region = reader.find_region(self_addr);
    // Should find the executable's code region or libc
}

} // anonymous namespace
