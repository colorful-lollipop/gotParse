# ============================================================================
# Dependencies.cmake
# ============================================================================
# Manages external dependencies using FetchContent

include(FetchContent)

# ----------------------------------------------------------------------------
# ELFIO - ELF file parsing library
# ----------------------------------------------------------------------------
message(STATUS "Fetching ELFIO...")

FetchContent_Declare(
    elfio
    GIT_REPOSITORY https://github.com/serge1/ELFIO.git
    GIT_TAG Release_3.12
)

FetchContent_MakeAvailable(elfio)

message(STATUS "  ELFIO source: ${elfio_SOURCE_DIR}")

# ----------------------------------------------------------------------------
# GTest - for unit tests (only when BUILD_TESTS is ON)
# ----------------------------------------------------------------------------
if(BUILD_TESTS)
    message(STATUS "Fetching GoogleTest...")

    FetchContent_Declare(
        googletest
        GIT_REPOSITORY https://github.com/google/googletest.git
        GIT_TAG release-1.12.1
    )

    # GTest options
    set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)
    set(INSTALL_GTEST OFF CACHE BOOL "" FORCE)
    set(BUILD_GMOCK OFF CACHE BOOL "" FORCE)

    FetchContent_MakeAvailable(googletest)

    message(STATUS "  GTest source: ${googletest_SOURCE_DIR}")
endif()
