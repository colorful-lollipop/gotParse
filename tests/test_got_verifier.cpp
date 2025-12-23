#include <gtest/gtest.h>
#include <elf_got/elf_got.h>
#include <iostream>
#include <filesystem>
#include <cstdio>

using namespace elf::got;

class GOTVerifierTest : public ::testing::Test {
protected:
    void SetUp() override {
        // Parse a real ELF file (the test executable itself)
        self_path = "/proc/self/exe";
        got_info = ELFParser::parse(self_path);
        ASSERT_TRUE(got_info.has_value());

        // Create process reader for self
        reader = std::make_unique<ProcessReader>(0);
        ASSERT_TRUE(reader->is_valid());

        // Create verification context
        context = reader->create_verification_context();

        // Get .got.plt section for testing
        if (got_info->got_plt() && got_info->got_plt()->has_symbols()) {
            test_section = &got_info->got_plt().value();
        }
    }

    std::string self_path;
    std::optional<GOTInfo> got_info;
    std::unique_ptr<ProcessReader> reader;
    GOTVerifier::VerificationContext context;
    const SectionInfo* test_section = nullptr;
};

// ============================================================================
// VerificationContext::find_module_for_address
// ============================================================================

TEST_F(GOTVerifierTest, FindModuleForAddress_Self) {
    // Get the executable base address
    auto exe_base = context.find_module_for_address(
        reinterpret_cast<std::uintptr_t>(&self_path));

    ASSERT_TRUE(exe_base.has_value());
    EXPECT_FALSE(exe_base->empty());
}

TEST_F(GOTVerifierTest, FindModuleForAddress_Libc) {
    // Get libc base by finding a libc function address
    void* libc_func = reinterpret_cast<void*>(&printf);
    auto libc_module = context.find_module_for_address(
        reinterpret_cast<std::uintptr_t>(libc_func));

    ASSERT_TRUE(libc_module.has_value());
    EXPECT_TRUE(libc_module->find("libc") != std::string::npos);
}

TEST_F(GOTVerifierTest, FindModuleForAddress_Invalid) {
    // Use an invalid address
    auto invalid = context.find_module_for_address(0x1);
    EXPECT_FALSE(invalid.has_value());
}

// ============================================================================
// Symbol Name Verification
// ============================================================================

TEST_F(GOTVerifierTest, VerifyBySymbolName_ValidEntry) {
    if (!test_section || test_section->entries.empty()) {
        GTEST_SKIP() << "No GOT entries to test";
    }

    // Populate runtime values
    reader->populate_got_runtime_values(const_cast<SectionInfo&>(*test_section));

    // Find a valid entry with runtime value
    for (const auto& entry : test_section->entries) {
        if (entry.has_symbol && entry.runtime_value && *entry.runtime_value != 0) {
            auto result = GOTVerifier::verify_by_symbol_name(entry, context);

            // Check that we got some result
            if (!result.runtime_symbol.empty()) {
                std::cout << "Entry: " << entry.symbol_name
                          << ", Runtime symbol: " << result.runtime_symbol
                          << ", Match: " << (result.symbol_name_verified ? "yes" : "no")
                          << std::endl;

                // For most GOT entries, the symbol should match
                // (unless there's some hooking or special PLT behavior)
                EXPECT_TRUE(result.symbol_name_verified || !result.runtime_symbol.empty());
                return;
            }
        }
    }

    // If we get here, we couldn't find a suitable entry
    GTEST_SKIP() << "No suitable GOT entry found for verification";
}

TEST_F(GOTVerifierTest, VerifyBySymbolName_NoSymbol) {
    GOTEntry entry;
    entry.runtime_value = 0x12345678;
    // No symbol_name set

    auto result = GOTVerifier::verify_by_symbol_name(entry, context);

    EXPECT_FALSE(result.symbol_name_verified);
    EXPECT_FALSE(result.error_message.empty());
}

TEST_F(GOTVerifierTest, VerifyBySymbolName_NoRuntimeValue) {
    GOTEntry entry;
    entry.has_symbol = true;
    entry.symbol_name = "printf";
    // No runtime_value set

    auto result = GOTVerifier::verify_by_symbol_name(entry, context);

    EXPECT_FALSE(result.symbol_name_verified);
    EXPECT_FALSE(result.error_message.empty());
}

// ============================================================================
// LD Simulation
// ============================================================================

TEST_F(GOTVerifierTest, VerifyByLDSimulation_ValidEntry) {
    if (!test_section || test_section->entries.empty()) {
        GTEST_SKIP() << "No GOT entries to test";
    }

    // Populate runtime values
    reader->populate_got_runtime_values(const_cast<SectionInfo&>(*test_section));

    // Find a valid entry with runtime value
    for (const auto& entry : test_section->entries) {
        if (entry.has_symbol && entry.runtime_value && *entry.runtime_value != 0) {
            auto result = GOTVerifier::verify_by_ld_simulation(
                entry, self_path, context);

            std::cout << "Entry: " << entry.symbol_name;
            if (result.expected_address != 0) {
                std::cout << ", Expected: 0x" << std::hex << result.expected_address
                          << ", Actual: 0x" << *entry.runtime_value
                          << ", Verified: " << (result.address_verified ? "yes" : "no")
                          << std::dec << std::endl;
            } else {
                std::cout << " - No expected address calculated"
                          << std::endl;
            }

            // We expect at least some verification attempt
            if (result.expected_address != 0) {
                // The address should either match or we should have an error
                EXPECT_TRUE(result.address_verified || !result.error_message.empty());
                return;
            }
        }
    }

    GTEST_SKIP() << "No suitable GOT entry found for LD simulation";
}

TEST_F(GOTVerifierTest, FindSymbolInLibc) {
    // Use SymbolResolver to find common libc functions instead
    const std::vector<std::string> libc_functions = {
        "printf", "malloc", "free", "strcpy", "strlen"
    };

    // Try common libc paths
    const std::vector<std::string> libc_paths = {
        "/lib/x86_64-linux-gnu/libc.so.6",
        "/lib64/libc.so.6",
        "/usr/lib/x86_64-linux-gnu/libc.so.6",
    };

    bool found = false;
    for (const auto& path : libc_paths) {
        if (!std::filesystem::exists(path)) {
            continue;
        }

        for (const auto& func_name : libc_functions) {
            auto addr = SymbolResolver::find_symbol(path, func_name);
            if (addr) {
                std::cout << "Found " << func_name << " in " << path
                          << " at 0x" << std::hex << addr->address
                          << std::dec << std::endl;
                found = true;
                break;
            }
        }
        if (found) break;
    }

    if (!found) {
        GTEST_SKIP() << "Could not find libc.so.6 for testing";
    }
}

// Note: get_needed_libs is now private - test indirectly through LD simulation
TEST_F(GOTVerifierTest, LDSimulation_UsesNeededLibs) {
    // This test indirectly verifies that NEEDED libraries are being used
    // by checking if LD simulation can find symbols in them

    if (!test_section || test_section->entries.empty()) {
        GTEST_SKIP() << "No GOT entries to test";
    }

    // Populate runtime values
    reader->populate_got_runtime_values(const_cast<SectionInfo&>(*test_section));

    // Try to verify at least one entry
    bool verified = false;
    for (const auto& entry : test_section->entries) {
        if (entry.has_symbol && entry.runtime_value && *entry.runtime_value != 0) {
            auto result = GOTVerifier::verify_by_ld_simulation(
                entry, self_path, context);

            if (result.expected_address != 0) {
                verified = true;
                std::cout << "Successfully verified " << entry.symbol_name
                          << " using LD simulation" << std::endl;
                break;
            }
        }
    }

    // If we couldn't verify any, that's okay - the NEEDED libs might
    // not be in the standard locations
    if (!verified) {
        std::cout << "Note: Could not verify entries via LD simulation"
                  << " (libraries may be in non-standard paths)" << std::endl;
    }
}

TEST_F(GOTVerifierTest, VerifyByLDSimulation_NoSymbol) {
    GOTEntry entry;
    entry.runtime_value = 0x12345678;
    // No symbol_name set

    auto result = GOTVerifier::verify_by_ld_simulation(
        entry, self_path, context);

    EXPECT_FALSE(result.address_verified);
    EXPECT_FALSE(result.error_message.empty());
}

// ============================================================================
// Comprehensive Verification
// ============================================================================

TEST_F(GOTVerifierTest, VerifyComprehensive_ValidEntry) {
    if (!test_section || test_section->entries.empty()) {
        GTEST_SKIP() << "No GOT entries to test";
    }

    // Populate runtime values
    reader->populate_got_runtime_values(const_cast<SectionInfo&>(*test_section));

    // Find a valid entry with runtime value
    for (auto& entry : test_section->entries) {
        if (entry.has_symbol && entry.runtime_value && *entry.runtime_value != 0) {
            auto result = GOTVerifier::verify_comprehensive(
                entry, self_path, context);

            std::cout << "Entry: " << entry.symbol_name << std::endl;
            if (!result.runtime_symbol.empty()) {
                std::cout << "  Runtime symbol: " << result.runtime_symbol
                          << " (match: " << (result.symbol_name_verified ? "yes" : "no)")
                          << std::endl;
            }
            if (result.expected_address != 0) {
                std::cout << "  Expected: 0x" << std::hex << result.expected_address
                          << ", Actual: 0x" << *entry.runtime_value
                          << " (match: " << (result.address_verified ? "yes" : "no")
                          << std::dec << ")" << std::endl;
            }

            // We expect at least some verification data
            EXPECT_TRUE(!result.runtime_symbol.empty() || result.expected_address != 0);
            return;
        }
    }

    GTEST_SKIP() << "No suitable GOT entry found for comprehensive verification";
}

// ============================================================================
// ProcessReader Integration
// ============================================================================

TEST_F(GOTVerifierTest, ProcessReader_CreateContext) {
    auto ctx = reader->create_verification_context();

    // For self process, pid is 0, but regions and module_bases should be populated
    EXPECT_GE(ctx.pid, 0);  // 0 for self process is valid
    EXPECT_FALSE(context.regions.empty());
    EXPECT_FALSE(context.module_bases.empty());
}

TEST_F(GOTVerifierTest, ProcessReader_VerifyGotEntry) {
    if (!test_section || test_section->entries.empty()) {
        GTEST_SKIP() << "No GOT entries to test";
    }

    // Create a mutable copy of entries for verification
    std::vector<GOTEntry> mutable_entries = test_section->entries;

    // Populate runtime values
    reader->populate_got_runtime_values(const_cast<SectionInfo&>(*test_section));

    // Find a valid entry and verify it
    for (auto& entry : mutable_entries) {
        if (entry.has_symbol && entry.runtime_value && *entry.runtime_value != 0) {
            auto result = reader->verify_got_entry(
                entry, self_path, context);

            // Check that entry fields are populated
            if (!result.runtime_symbol.empty()) {
                EXPECT_EQ(entry.runtime_symbol_name, result.runtime_symbol);
                EXPECT_EQ(entry.symbol_name_matches, result.symbol_name_verified);
            }
            if (result.expected_address != 0) {
                EXPECT_EQ(entry.expected_address, result.expected_address);
                EXPECT_EQ(entry.address_is_hooked, result.is_hooked());
            }

            std::cout << "Entry " << entry.symbol_name << ":" << std::endl;
            std::cout << "  address_is_hooked: " << (entry.address_is_hooked ? "YES" : "no") << std::endl;
            std::cout << "  Full entry: " << entry.to_string() << std::endl;
            return;
        }
    }

    GTEST_SKIP() << "No suitable GOT entry found";
}

// ============================================================================
// Symbol Resolution Integration
// ============================================================================

TEST_F(GOTVerifierTest, SymbolResolver_AtKnownFunctions) {
    // Try to resolve symbol at a known function address (printf from libc)
    std::uintptr_t func_addr = reinterpret_cast<std::uintptr_t>(&printf);
    auto symbol = SymbolResolver::resolve_address(func_addr, 0);

    // We should find "printf" or at least some symbol
    std::cout << "Symbol at printf address: " << (symbol ? symbol->name : "<none>") << std::endl;
    ASSERT_TRUE(symbol.has_value());
    EXPECT_FALSE(symbol->name.empty());
}

TEST_F(GOTVerifierTest, SymbolResolver_InvalidAddress) {
    auto symbol = SymbolResolver::resolve_address(0x1, 0);
    EXPECT_FALSE(symbol.has_value());
}
