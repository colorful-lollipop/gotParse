# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Build Commands

```bash
# Standard build (Release is default)
mkdir build && cd build
cmake ..
make

# Build with tests and run them
cmake -DBUILD_TESTS=ON ..
make test

# Build with coverage
cmake -DENABLE_COVERAGE=ON ..
make coverage

# Build with warnings as errors
cmake -DENABLE_WERROR=ON ..

# Minimal build (no tests/examples)
cmake -DBUILD_TESTS=OFF -DBUILD_EXAMPLES=OFF ..
```

### Build Options

| Option | Default | Purpose |
|--------|---------|---------|
| `BUILD_TESTS` | `ON` | Build unit tests (Google Test) |
| `BUILD_EXAMPLES` | `ON` | Build example programs and CLI tool |
| `ENABLE_COVERAGE` | `OFF` | Enable coverage reports (requires lcov/genhtml) |
| `ENABLE_WERROR` | `OFF` | Treat warnings as errors |

### Running Tests

```bash
# Run all tests
cd build && make test

# Run test executable directly
cd build && ./bin/elf_got_tests

# Run specific test filter
cd build && ./bin/elf_got_tests --gtest_filter="TestSuite.TestCase"
```

## Code Architecture

### Core Components

The project is a C++ library (`elf_got_core`) plus a CLI tool for analyzing ELF Global Offset Table (GOT) sections.

```
gotPrase/
├── include/elf_got/          # Public API headers
│   └── elf_got.h             # Main entry point (includes all components)
├── src/
│   ├── core/                 # ELF parsing
│   │   ├── types.h/cpp       # Core data structures (GOTEntry, SectionInfo, GOTInfo, etc.)
│   │   └── elf_parser.h/cpp  # ELF file parsing using ELFIO
│   ├── process/              # Runtime process analysis
│   │   ├── maps_parser.h/cpp     # /proc/pid/maps parsing
│   │   └── process_reader.h/cpp  # /proc/pid/mem reading, GOT hook detection
│   ├── symbol/               # Symbol resolution
│   │   └── symbol_resolver.h/cpp # dladdr and ELF-based resolution
│   └── main.cpp              # CLI tool
├── examples/                 # Example programs
└── tests/                    # Unit tests (Google Test)
```

### Key Data Structures (namespace `elf::got`)

- **`GOTEntry`**: Single GOT entry with offset, virtual address, symbol info, and optional runtime value
- **`SectionInfo`**: ELF section (`.got` or `.got.plt`) with entries and runtime base address
- **`GOTInfo`**: Container for both GOT sections (optional .got and .got.plt)
- **`MemoryRegion`**: Memory region parsed from /proc/pid/maps
- **`SymbolInfo`**: Resolved symbol with name, address, module, type

### Library API Usage

All classes are in namespace `elf::got`:

```cpp
#include <elf_got/elf_got.h>

// Parse ELF file
auto got_info = elf::got::ELFParser::parse("/bin/ls");

// Parse process memory maps
auto maps = elf::got::MapsParser::parse(pid);

// Read process memory and detect GOT hooks
elf::got::ProcessReader reader(pid);
reader.populate_got_runtime_values(section);
reader.detect_hooks(section);

// Resolve address to symbol
auto symbol = elf::got::SymbolResolver::resolve_address(addr, pid);
```

### Dependencies

- **ELFIO v3.12** (via FetchContent) - ELF file parsing
- **Google Test v1.12.1** (via FetchContent) - Testing framework
- **System**: `libdl`, `pthread`

## Code Style

This project uses strict compiler warnings configured in `.clangd`:

- C++17 standard
- Clang-Tidy checks: modernize, performance, bugprone, cppcoreguidelines
- Prefer `nullptr`, `override`, `auto`
- No old-style C casts
- All functions marked `[[nodiscard]]` where return value should not be ignored

The `.clangd` file is the source of truth for code style - consult it for enabled clang-tidy checks.

## Testing

Tests are located in `tests/`:
- `test_types.cpp` - Core data structure tests
- `test_elf_parser.cpp` - ELF parsing tests
- `test_maps_parser.cpp` - /proc/pid/maps parsing tests
- `test_process_reader.cpp` - Process memory reading tests
- `test_symbol_resolver.cpp` - Symbol resolution tests
- `test_readelf_verification.cpp` - Verification against readelf/objdump output

When adding new functionality, add corresponding tests following the existing Google Test patterns.
