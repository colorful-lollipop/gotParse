# ============================================================================
# Tests CMakeLists.txt
# ============================================================================
# Standalone test configuration

enable_testing()

# ----------------------------------------------------------------------------
# Test executable
# ----------------------------------------------------------------------------
add_executable(elf_got_tests
    main.cpp
    test_types.cpp
    test_elf_parser.cpp
    test_maps_parser.cpp
    test_process_reader.cpp
    test_symbol_resolver.cpp
    test_readelf_verification.cpp
)

target_include_directories(elf_got_tests PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/../src)

target_link_libraries(elf_got_tests PRIVATE
    elf_got_core
    gtest_main
)

# ----------------------------------------------------------------------------
# Coverage support
# ----------------------------------------------------------------------------
if(ENABLE_COVERAGE)
    target_compile_options(elf_got_core PUBLIC --coverage)
    target_link_options(elf_got_tests PRIVATE --coverage)

    # Coverage report target
    find_program(LCOV lcov)
    find_program(GENHTML genhtml)

    if(LCOV AND GENHTML)
        add_custom_target(coverage
            COMMAND ${LCOV} --capture --directory . --output-file coverage.info
            COMMAND ${LCOV} --remove coverage.info
                '/usr/*'
                '${elfio_SOURCE_DIR}/*'
                '${googletest_SOURCE_DIR}/*'
                --output-file coverage.info
            COMMAND ${GENHTML} coverage.info --output-directory coverage_html
            COMMENT "Generating code coverage report"
            WORKING_DIRECTORY ${CMAKE_BINARY_DIR}
        )
        message(STATUS "Coverage target enabled: make coverage")
    else()
        message(WARNING "lcov/genhtml not found - coverage disabled")
    endif()
endif()

# ----------------------------------------------------------------------------
# Test discovery
# ----------------------------------------------------------------------------
include(GoogleTest)
gtest_discover_tests(elf_got_tests)

# ----------------------------------------------------------------------------
# Summary
# ----------------------------------------------------------------------------
message(STATUS "")
message(STATUS "  Tests configured:")
message(STATUS "    elf_got_tests")
message(STATUS "")
