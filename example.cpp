#include <elf_got/elf_got.h>
#include <dlfcn.h>
#include <iostream>
#include <iomanip>

using namespace elf::got;

void print_section_info(const SectionInfo &section) {
  std::cout << "  Section: " << section.name << "\n"
            << "    Virtual Address: 0x" << std::hex << section.virtual_addr
            << "\n"
            << "    File Offset:     0x" << std::hex << section.file_offset
            << "\n"
            << "    Size:            " << std::dec << section.size << " bytes\n"
            << "    Entry Count:     ~" << section.entry_count() << "\n";
}

void print_got_symbols(const SectionInfo &section) {
  const auto &entries = section.entries;

  // Count entries with symbols
  int symbol_count = 0;
  for (const auto &entry : entries) {
    if (entry.has_symbol) {
      symbol_count++;
    }
  }

  if (symbol_count == 0) {
    std::cout << "  No symbols found for this section.\n\n";
    return;
  }

  std::cout << "  Found " << symbol_count << " symbol(s):\n\n";

  // Print header
  std::cout << "    "
            << std::left << std::setw(4)  << "Idx"
            << " " << std::right << std::setw(8) << "Offset"
            << " " << std::setw(16) << "Address"
            << "  " << std::left << std::setw(30) << "Symbol"
            << "\n";
  std::cout << "    "
            << std::left << std::setw(4)  << "---"
            << " " << std::right << std::setw(8) << "------"
            << " " << std::setw(16) << "-------"
            << "  " << std::left << std::setw(30) << "------"
            << "\n";

  // Print entries
  int idx = 0;
  for (const auto &entry : entries) {
    if (entry.has_symbol) {
      std::cout << "    "
                << std::left << std::setw(4) << idx++
                << " " << std::right << std::setw(8) << std::hex << entry.offset
                << " " << std::setw(16) << entry.va
                << "  " << std::left << std::setw(30) << entry.symbol_name
                << "\n";
    }
  }
  std::cout << "\n";
}

int main(int argc, char *argv[]) {
  if (argc != 2) {
    std::cerr << "Usage: " << argv[0] << " <path_to_so>\n";
    return 1;
  }

  // Parse ELF file using ELFIO (returns std::optional)
  auto got_info_opt = ELFParser::parse(argv[1]);

  if (!got_info_opt) {
    std::cerr << "Error: Failed to parse ELF file\n";
    return 1;
  }

  // Get GOT info
  const auto &got_info = *got_info_opt;

  std::cout << "=== GOT Sections Analysis ===\n\n";

  // Print .got.plt
  if (const auto &got_plt = got_info.got_plt()) {
    std::cout << "[.got.plt] Function GOT (Primary Hook Target)\n";
    print_section_info(*got_plt);
    std::cout << "  Purpose: External function addresses\n";
    std::cout << "  Hook Target: YES ★★★\n";
    print_got_symbols(*got_plt);
  }

  // Print .got
  if (const auto &got = got_info.got()) {
    std::cout << "[.got] Data GOT\n";
    print_section_info(*got);
    std::cout << "  Purpose: Global variable addresses\n";
    std::cout << "  Hook Target: Sometimes\n";
    print_got_symbols(*got);
  }

  return 0;
}