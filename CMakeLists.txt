cmake_minimum_required(VERSION 3.15)
project(elf_got_parser VERSION 1.0.0 LANGUAGES CXX)

# ============================================================================
# Project Options
# ============================================================================
option(BUILD_TESTS "Build unit tests" ON)
option(BUILD_EXAMPLES "Build example executables" ON)
option(ENABLE_COVERAGE "Enable code coverage reporting" OFF)
option(ENABLE_WERROR "Treat warnings as errors" OFF)

# ============================================================================
# C++ Standard
# ============================================================================
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# ============================================================================
# Output Directories
# ============================================================================
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)

# ============================================================================
# Compiler Flags (Linux/Unix only)
# ============================================================================
add_compile_options(
    -Wall -Wextra -Wpedantic
)

if(ENABLE_WERROR)
    add_compile_options(-Werror)
endif()

# Debug flags
set(CMAKE_CXX_FLAGS_DEBUG "-g -O0")

# Release flags
set(CMAKE_CXX_FLAGS_RELEASE "-O3 -DNDEBUG")

# ============================================================================
# Default Build Type
# ============================================================================
if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
    message(STATUS "Setting build type to 'Release' as none was specified.")
    set(CMAKE_BUILD_TYPE Release CACHE STRING "Build type" FORCE)
    set_property(CACHE CMAKE_BUILD_TYPE PROPERTY STRINGS "Debug" "Release" "MinSizeRel" "RelWithDebInfo")
endif()

# ============================================================================
# Dependencies
# ============================================================================
include(cmake/Dependencies.cmake)

# ============================================================================
# Core Library
# ============================================================================
add_library(elf_got_core STATIC
    src/core/types.cpp
    src/core/elf_parser.cpp
    src/process/maps_parser.cpp
    src/process/process_reader.cpp
    src/symbol/symbol_resolver.cpp
)

target_include_directories(elf_got_core PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:include>
)

target_include_directories(elf_got_core PRIVATE
    ${elfio_SOURCE_DIR}
)

target_link_libraries(elf_got_core PUBLIC
    ${CMAKE_DL_LIBS}
    pthread
)

# ============================================================================
# Executable
# ============================================================================
if(BUILD_EXAMPLES)
    add_executable(elf_got src/main.cpp)
    target_link_libraries(elf_got PRIVATE elf_got_core)

    # Legacy example (backward compatibility)
    add_executable(example example.cpp)
    target_link_libraries(example PRIVATE elf_got_core)

    # Examples directory
    add_subdirectory(examples)
endif()

# ============================================================================
# Tests
# ============================================================================
if(BUILD_TESTS)
    add_subdirectory(tests)
endif()

# ============================================================================
# Installation
# ============================================================================
include(GNUInstallDirs)

install(TARGETS elf_got_core
    EXPORT elf_got_targets
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
)

install(DIRECTORY include/
    DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
)

install(EXPORT elf_got_targets
    FILE elf_got-config.cmake
    NAMESPACE elf_got::
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/elf_got
)

# ============================================================================
# Configuration Summary
# ============================================================================
message(STATUS "")
message(STATUS "========================================")
message(STATUS "  ELF GOT Parser v${PROJECT_VERSION}")
message(STATUS "========================================")
message(STATUS "  Build Type:    ${CMAKE_BUILD_TYPE}")
message(STATUS "  C++ Standard:  ${CMAKE_CXX_STANDARD}")
message(STATUS "  Build Tests:   ${BUILD_TESTS}")
message(STATUS "  Build Examples:${BUILD_EXAMPLES}")
message(STATUS "  Enable Coverage: ${ENABLE_COVERAGE}")
message(STATUS "  Werror:       ${ENABLE_WERROR}")
message(STATUS "========================================")
message(STATUS "")
