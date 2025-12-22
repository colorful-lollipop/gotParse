#include <elf_got/elf_got.h>
#include <gtest/gtest.h>

using namespace elf::got;

namespace {

// Test GOTEntry
TEST(GOTEntryTest, DefaultConstruction) {
    GOTEntry entry;

    EXPECT_EQ(entry.offset, 0);
    EXPECT_EQ(entry.va, 0);
    EXPECT_TRUE(entry.symbol_name.empty());
    EXPECT_EQ(entry.symbol_index, 0);
    EXPECT_FALSE(entry.has_symbol);
    EXPECT_FALSE(entry.runtime_value.has_value());
    EXPECT_FALSE(entry.address_matches);
    EXPECT_FALSE(entry.is_valid());
}

TEST(GOTEntryTest, ValidEntry) {
    GOTEntry entry;
    entry.offset = 0x1000;
    entry.va = 0x5000;
    entry.symbol_name = "malloc";
    entry.symbol_index = 42;
    entry.has_symbol = true;

    EXPECT_EQ(entry.offset, 0x1000);
    EXPECT_EQ(entry.va, 0x5000);
    EXPECT_EQ(entry.symbol_name, "malloc");
    EXPECT_EQ(entry.symbol_index, 42);
    EXPECT_TRUE(entry.has_symbol);
    EXPECT_TRUE(entry.is_valid());
}

TEST(GOTEntryTest, RuntimeValue) {
    GOTEntry entry;
    entry.offset = 8;
    entry.va = 0x4008;
    entry.runtime_value = 0x7f1234567890;
    entry.address_matches = true;

    ASSERT_TRUE(entry.runtime_value.has_value());
    EXPECT_EQ(*entry.runtime_value, 0x7f1234567890);
    EXPECT_TRUE(entry.address_matches);
}

TEST(GOTEntryTest, ToString) {
    GOTEntry entry;
    entry.offset = 0x10;
    entry.va = 0x4000;
    entry.symbol_name = "printf";
    entry.has_symbol = true;
    entry.runtime_value = 0x7f0000123456;
    entry.address_matches = true;

    std::string str = entry.to_string();
    EXPECT_FALSE(str.empty());
    EXPECT_NE(str.find("printf"), std::string::npos);
}

// Test MemoryRegion
TEST(MemoryRegionTest, DefaultConstruction) {
    MemoryRegion region;

    EXPECT_EQ(region.start, 0);
    EXPECT_EQ(region.end, 0);
    EXPECT_EQ(region.offset, 0);
    EXPECT_TRUE(region.perms.empty());
    EXPECT_TRUE(region.pathname.empty());
}

TEST(MemoryRegionTest, Size) {
    MemoryRegion region;
    region.start = 0x1000;
    region.end = 0x2000;

    EXPECT_EQ(region.size(), 0x1000);
}

TEST(MemoryRegionTest, Contains) {
    MemoryRegion region;
    region.start = 0x1000;
    region.end = 0x2000;

    EXPECT_TRUE(region.contains(0x1000));
    EXPECT_TRUE(region.contains(0x1500));
    EXPECT_TRUE(region.contains(0x1fff));   // contained (0x1fff < 0x2000)
    EXPECT_FALSE(region.contains(0x2000));  // not contained (end is exclusive)
    EXPECT_FALSE(region.contains(0xfff));
}

TEST(MemoryRegionTest, PermissionChecks) {
    MemoryRegion region;
    region.perms = "r-xp";

    EXPECT_TRUE(region.is_readable());
    EXPECT_FALSE(region.is_writable());
    EXPECT_TRUE(region.is_executable());
    EXPECT_TRUE(region.is_private());
    EXPECT_FALSE(region.is_shared());

    region.perms = "rw-s";
    EXPECT_TRUE(region.is_readable());
    EXPECT_TRUE(region.is_writable());
    EXPECT_FALSE(region.is_executable());
    EXPECT_FALSE(region.is_private());
    EXPECT_TRUE(region.is_shared());
}

TEST(MemoryRegionTest, ToString) {
    MemoryRegion region;
    region.start = 0x400000;
    region.end = 0x401000;
    region.perms = "r-xp";
    region.offset = 0;
    region.dev = "08:01";
    region.inode = "12345";
    region.pathname = "/lib/libc.so.6";

    std::string str = region.to_string();
    EXPECT_FALSE(str.empty());
    EXPECT_NE(str.find("libc.so.6"), std::string::npos);
}

// Test SymbolInfo
TEST(SymbolInfoTest, DefaultConstruction) {
    SymbolInfo info;

    EXPECT_TRUE(info.name.empty());
    EXPECT_TRUE(info.demangled_name.empty());
    EXPECT_EQ(info.address, 0);
    EXPECT_EQ(info.size, 0);
    EXPECT_TRUE(info.module_name.empty());
    EXPECT_TRUE(info.type.empty());
    EXPECT_FALSE(info.is_valid());
    EXPECT_FALSE(info.is_function());
}

TEST(SymbolInfoTest, ValidSymbol) {
    SymbolInfo info;
    info.name = "_Z3fooi";  // mangled "foo(int)"
    info.demangled_name = "foo(int)";
    info.address = 0x4000;
    info.size = 16;
    info.module_name = "libtest.so";
    info.type = "FUNC";

    EXPECT_TRUE(info.is_valid());
    EXPECT_TRUE(info.is_function());
    EXPECT_EQ(info.display_name(), "foo(int)");
}

TEST(SymbolInfoTest, DisplayName) {
    SymbolInfo info;
    info.name = "malloc";
    info.type = "FUNC";

    EXPECT_EQ(info.display_name(), "malloc");

    info.demangled_name = "malloc";
    EXPECT_EQ(info.display_name(), "malloc");

    info.name = "_Z3barv";
    info.demangled_name = "bar()";
    EXPECT_EQ(info.display_name(), "bar()");
}

TEST(SymbolInfoTest, ToString) {
    SymbolInfo info;
    info.name = "test_func";
    info.address = 0x1000;
    info.size = 32;
    info.module_name = "libtest.so";
    info.type = "FUNC";

    std::string str = info.to_string();
    EXPECT_FALSE(str.empty());
    EXPECT_NE(str.find("test_func"), std::string::npos);
    EXPECT_NE(str.find("libtest.so"), std::string::npos);
}

// Test SectionInfo
TEST(SectionInfoTest, DefaultConstruction) {
    SectionInfo section;

    EXPECT_TRUE(section.name.empty());
    EXPECT_EQ(section.virtual_addr, 0);
    EXPECT_EQ(section.file_offset, 0);
    EXPECT_EQ(section.size, 0);
    EXPECT_EQ(section.base_addr, 0);
    EXPECT_TRUE(section.entries.empty());
    EXPECT_EQ(section.entry_count(), 0);
    EXPECT_FALSE(section.is_valid());
    EXPECT_FALSE(section.has_symbols());
}

TEST(SectionInfoTest, EntryCount) {
    SectionInfo section;
    section.size = 64;  // 8 pointers on 64-bit

    EXPECT_EQ(section.entry_count(), 64 / sizeof(void*));
}

TEST(SectionInfoTest, RuntimeAddress) {
    SectionInfo section;
    section.virtual_addr = 0x3000;
    section.base_addr = 0x400000;

    EXPECT_EQ(section.runtime_address(), 0x403000);
}

TEST(SectionInfoTest, HasSymbols) {
    SectionInfo section;
    section.size = 16;

    GOTEntry entry1;
    entry1.has_symbol = true;
    entry1.symbol_name = "func1";
    section.entries.push_back(entry1);

    GOTEntry entry2;
    entry2.has_symbol = false;
    section.entries.push_back(entry2);

    EXPECT_TRUE(section.has_symbols());
}

TEST(SectionInfoTest, ValidateAddresses) {
    SectionInfo section;
    section.size = 16;

    GOTEntry entry1;
    entry1.runtime_value = 0x1000;
    entry1.address_matches = true;
    section.entries.push_back(entry1);

    GOTEntry entry2;
    entry2.runtime_value = 0x2000;
    entry2.address_matches = false;
    section.entries.push_back(entry2);

    GOTEntry entry3;
    entry3.runtime_value = 0x3000;
    entry3.address_matches = true;
    section.entries.push_back(entry3);

    EXPECT_EQ(section.validate_addresses(), 2);
}

// Test GOTInfo
TEST(GOTInfoTest, DefaultConstruction) {
    GOTInfo info;

    EXPECT_FALSE(info.got().has_value());
    EXPECT_FALSE(info.got_plt().has_value());
    EXPECT_FALSE(info.has_got_sections());
    EXPECT_TRUE(info.all_sections().empty());
}

TEST(GOTInfoTest, SetGot) {
    GOTInfo info;

    SectionInfo got;
    got.name = ".got";
    got.size = 64;
    info.set_got(std::move(got));

    EXPECT_TRUE(info.got().has_value());
    EXPECT_EQ(info.got()->name, ".got");
    EXPECT_TRUE(info.has_got_sections());
    EXPECT_EQ(info.all_sections().size(), 1);
}

TEST(GOTInfoTest, SetGotPlt) {
    GOTInfo info;

    SectionInfo got_plt;
    got_plt.name = ".got.plt";
    got_plt.size = 32;
    info.set_got_plt(std::move(got_plt));

    EXPECT_TRUE(info.got_plt().has_value());
    EXPECT_EQ(info.got_plt()->name, ".got.plt");
    EXPECT_TRUE(info.has_got_sections());
    EXPECT_EQ(info.all_sections().size(), 1);
}

TEST(GOTInfoTest, BothSections) {
    GOTInfo info;

    SectionInfo got;
    got.name = ".got";
    got.size = 64;

    SectionInfo got_plt;
    got_plt.name = ".got.plt";
    got_plt.size = 32;

    info.set_got(std::move(got));
    info.set_got_plt(std::move(got_plt));

    EXPECT_TRUE(info.got().has_value());
    EXPECT_TRUE(info.got_plt().has_value());
    EXPECT_TRUE(info.has_got_sections());
    EXPECT_EQ(info.all_sections().size(), 2);
}

TEST(GOTInfoTest, CalculateRuntimeAddress) {
    SectionInfo section;
    section.virtual_addr = 0x2000;

    void* base = reinterpret_cast<void*>(0x400000);
    void* runtime = GOTInfo::calculate_runtime_address(base, section);

    EXPECT_EQ(runtime, reinterpret_cast<void*>(0x402000));
}

} // anonymous namespace
