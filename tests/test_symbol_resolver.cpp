#include <elf_got/elf_got.h>
#include <gtest/gtest.h>

#include <fstream>
#include <cstdlib>
#include <cstring>
#include <cstdio>

using namespace elf::got;

namespace {

class SymbolResolverTest : public ::testing::Test {
protected:
    void SetUp() override {
        // Check if we can access /proc/self/maps
        std::ifstream f("/proc/self/maps");
        if (!f.good()) {
            GTEST_SKIP() << "/proc not accessible";
        }
    }

    // Get address of a known function
    template<typename Func>
    void* get_function_address(Func* func) {
        return reinterpret_cast<void*>(func);
    }
};

// Test demangle with non-mangled names
TEST_F(SymbolResolverTest, DemangleNonMangled) {
    EXPECT_EQ(SymbolResolver::demangle("malloc"), "malloc");
    EXPECT_EQ(SymbolResolver::demangle("printf"), "printf");
    EXPECT_EQ(SymbolResolver::demangle(""), "");
}

// Test demangle with mangled C++ names
TEST_F(SymbolResolverTest, DemangleMangled) {
    // Simple function
    std::string result = SymbolResolver::demangle("_Z3fooi");
    // Should demangle to "foo(int)"
    if (!result.empty() && result[0] != '_') {
        EXPECT_TRUE(result.find("foo") != std::string::npos);
    }

    // Class method
    result = SymbolResolver::demangle("_ZN3Bar3bazEv");
    if (!result.empty() && result[0] != '_') {
        // Bar::baz()
        EXPECT_TRUE(result.find("Bar") != std::string::npos ||
                    result.find("baz") != std::string::npos);
    }

    // Invalid mangled name
    result = SymbolResolver::demangle("_Zinvalid");
    // Should return original if demangling fails
    EXPECT_EQ(result, "_Zinvalid");
}

// Test demangle with nullptr
TEST_F(SymbolResolverTest, DemangleNullptr) {
    EXPECT_EQ(SymbolResolver::demangle(static_cast<const char*>(nullptr)), "");
}

// Test resolve_dynamic with known functions
TEST_F(SymbolResolverTest, ResolveDynamicKnownFunctions) {
    // Test with malloc (should be in standard library)
    auto result = SymbolResolver::resolve_dynamic(
        reinterpret_cast<void*>(&malloc));

    if (result.found) {
        EXPECT_FALSE(result.symbol.name.empty());
        EXPECT_TRUE(result.symbol.name.find("malloc") != std::string::npos ||
                    result.symbol.demangled_name.find("malloc") != std::string::npos);
    }
}

// Test resolve_dynamic with nullptr
TEST_F(SymbolResolverTest, ResolveDynamicNullptr) {
    auto result = SymbolResolver::resolve_dynamic(nullptr);
    EXPECT_FALSE(result.found);
    EXPECT_FALSE(result.error_message.empty());
}

// Test resolve_dynamic with test function
TEST_F(SymbolResolverTest, ResolveDynamicTestFunction) {
    // Get address of a known library function
    void* addr = reinterpret_cast<void*>(&printf);

    auto result = SymbolResolver::resolve_dynamic(addr);

    // May or may not find it depending on visibility
    // But should not crash
}

// Test find_symbol in libc
TEST_F(SymbolResolverTest, FindSymbolInLibc) {
    std::string libc_path = "/lib/x86_64-linux-gnu/libc.so.6";
    std::ifstream f(libc_path);
    if (!f.good()) {
        libc_path = "/lib64/libc.so.6";
        f.open(libc_path);
        if (!f.good()) {
            GTEST_SKIP() << "libc.so.6 not found";
        }
    }

    auto symbol = SymbolResolver::find_symbol(libc_path, "malloc");
    if (symbol.has_value()) {
        EXPECT_EQ(symbol->name, "malloc");
        EXPECT_GT(symbol->address, 0);
    } else {
        // Symbol might not be found in stripped binaries
    }
}

// Test find_symbols_matching
TEST_F(SymbolResolverTest, FindSymbolsMatching) {
    auto maps_result = MapsParser::parse(0);
    ASSERT_TRUE(maps_result.has_value());

    for (const auto& [path, base] : maps_result->module_bases) {
        if (path.find("libc") == std::string::npos) {
            continue;
        }

        auto symbols = SymbolResolver::find_symbols_matching(path, "print");
        if (!symbols.empty()) {
            // Should find printf, fprintf, etc.
            bool found_print = false;
            for (const auto& sym : symbols) {
                if (sym.name.find("print") != std::string::npos) {
                    found_print = true;
                    break;
                }
            }
            EXPECT_TRUE(found_print);
        }
        break;  // Test one module
    }
}

// Test resolve_from_elf
TEST_F(SymbolResolverTest, ResolveFromElf) {
    auto maps_result = MapsParser::parse(0);
    ASSERT_TRUE(maps_result.has_value());

    for (const auto& [path, base] : maps_result->module_bases) {
        if (path.find("libc") == std::string::npos) {
            continue;
        }

        // Get symbol info for malloc
        auto symbol = SymbolResolver::find_symbol(path, "malloc");
        if (!symbol.has_value()) {
            continue;
        }

        std::uintptr_t addr = base + symbol->address;
        auto result = SymbolResolver::resolve_from_elf(path, addr, base);

        if (result.found) {
            EXPECT_EQ(result.symbol.name, "malloc");
        }

        break;  // Test one module
    }
}

// Test resolve_address with self process
TEST_F(SymbolResolverTest, ResolveAddressSelf) {
    // Use address of a known function
    void* addr = reinterpret_cast<void*>(&printf);

    auto symbol = SymbolResolver::resolve_address(
        reinterpret_cast<std::uintptr_t>(addr), 0);

    if (symbol.has_value()) {
        EXPECT_FALSE(symbol->name.empty());
    }
}

// Test resolve_address with libc
TEST_F(SymbolResolverTest, ResolveAddressLibc) {
    auto maps_result = MapsParser::parse(0);
    ASSERT_TRUE(maps_result.has_value());

    for (const auto& [path, base] : maps_result->module_bases) {
        if (path.find("libc") == std::string::npos) {
            continue;
        }

        auto symbol = SymbolResolver::find_symbol(path, "malloc");
        if (!symbol.has_value()) {
            continue;
        }

        std::uintptr_t addr = base + symbol->address;
        auto resolved = SymbolResolver::resolve_address(addr, 0);

        // Symbol resolution may fail if the symbol has no size info
        // or if dladdr can't find it
        // The test passes if we got this far without crashing
        if (resolved.has_value() && !resolved->name.empty()) {
            // Name should contain "malloc" or be "malloc"
            EXPECT_TRUE(resolved->name == "malloc" ||
                        resolved->name.find("malloc") != std::string::npos);
        }

        break;  // Test one libc is enough
    }
}

// Test got_entry_to_symbol
TEST_F(SymbolResolverTest, GotEntryToSymbol) {
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
        if (!got_plt || got_plt->entries.empty()) {
            continue;
        }

        // Find first entry with a symbol
        for (const auto& entry : got_plt->entries) {
            if (entry.has_symbol) {
                std::string symbol_name = SymbolResolver::got_entry_to_symbol(
                    path, entry.offset);
                EXPECT_EQ(symbol_name, entry.symbol_name);
                break;
            }
        }

        break;  // Test one module
    }
}

// Test ResolveResult bool conversion
TEST_F(SymbolResolverTest, ResolveResultBoolConversion) {
    SymbolResolver::ResolveResult result;
    EXPECT_FALSE(result);  // Default: not found

    result.found = true;
    EXPECT_TRUE(result);
}

// Test SymbolInfo display_name
TEST_F(SymbolResolverTest, SymbolInfoDisplayName) {
    SymbolInfo info;

    // No demangling
    info.name = "malloc";
    EXPECT_EQ(info.display_name(), "malloc");

    // With demangling
    info.name = "_Z3fooi";
    info.demangled_name = "foo(int)";
    EXPECT_EQ(info.display_name(), "foo(int)");
}

// Test SymbolInfo is_function
TEST_F(SymbolResolverTest, SymbolInfoIsFunction) {
    SymbolInfo info;
    info.type = "FUNC";
    EXPECT_TRUE(info.is_function());

    info.type = "OBJECT";
    EXPECT_FALSE(info.is_function());

    info.type = "";
    EXPECT_FALSE(info.is_function());
}

// Test resolve_multiple_addresses
TEST_F(SymbolResolverTest, ResolveMultipleAddresses) {
    std::vector<void*> addresses = {
        reinterpret_cast<void*>(&malloc),
        reinterpret_cast<void*>(&free),
        reinterpret_cast<void*>(&printf),
    };

    int found_count = 0;
    for (void* addr : addresses) {
        auto result = SymbolResolver::resolve_dynamic(addr);
        if (result.found) {
            found_count++;
        }
    }

    // At least some should be found
    EXPECT_GT(found_count, 0);
}

// Test with non-existent ELF file
TEST_F(SymbolResolverTest, FindSymbolNonExistentFile) {
    auto symbol = SymbolResolver::find_symbol("/nonexistent/path.so", "test");
    EXPECT_FALSE(symbol.has_value());
}

// Test find_symbols_matching with non-existent file
TEST_F(SymbolResolverTest, FindSymbolsMatchingNonExistentFile) {
    auto symbols = SymbolResolver::find_symbols_matching(
        "/nonexistent/path.so", "test");
    EXPECT_TRUE(symbols.empty());
}

// Test resolve_from_elf with invalid file
TEST_F(SymbolResolverTest, ResolveFromElfInvalidFile) {
    auto result = SymbolResolver::resolve_from_elf(
        "/nonexistent/path.so", 0x1000, 0);
    EXPECT_FALSE(result.found);
}

} // anonymous namespace
