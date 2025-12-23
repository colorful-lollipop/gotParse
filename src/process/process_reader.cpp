#include "process_reader.h"

#include <unistd.h>
#include <fcntl.h>
#include <cstring>
#include <csignal>
#include <sys/types.h>

namespace elf::got {

namespace {

/**
 * @brief Get the mem file path for a process
 */
[[nodiscard]] std::string get_mem_path(pid_t pid) noexcept {
    if (pid == 0) {
        return "/proc/self/mem";
    }
    return "/proc/" + std::to_string(static_cast<int>(pid)) + "/mem";
}

/**
 * @brief Check if process exists
 */
[[nodiscard]] bool process_exists(pid_t pid) noexcept {
    if (pid == 0) {
        return true;  // Self always exists
    }

    // Try to send signal 0 to check if process exists
    return kill(pid, 0) == 0 || errno != ESRCH;
}

} // anonymous namespace

ProcessReader::ProcessReader(pid_t pid) noexcept
    : pid_(pid), mem_fd_(-1) {
    static_cast<void>(open_mem_fd());  // May fail, but reader can still be used for maps
}

ProcessReader::~ProcessReader() noexcept {
    close_fd();
}

ProcessReader::ProcessReader(ProcessReader&& other) noexcept
    : pid_(other.pid_),
      mem_fd_(other.mem_fd_),
      cached_regions_(std::move(other.cached_regions_)) {
    other.mem_fd_ = -1;
}

ProcessReader& ProcessReader::operator=(ProcessReader&& other) noexcept {
    if (this != &other) {
        close_fd();
        pid_ = other.pid_;
        mem_fd_ = other.mem_fd_;
        cached_regions_ = std::move(other.cached_regions_);
        other.mem_fd_ = -1;
    }
    return *this;
}

bool ProcessReader::open_mem_fd() noexcept {
    if (!process_exists(pid_)) {
        return false;
    }

    const std::string mem_path = get_mem_path(pid_);
    mem_fd_ = ::open(mem_path.c_str(), O_RDONLY);

    if (mem_fd_ < 0) {
        // This can fail due to permissions - process might exist but we can't read it
        return false;
    }

    return true;
}

void ProcessReader::close_fd() noexcept {
    if (mem_fd_ >= 0) {
        ::close(mem_fd_);
        mem_fd_ = -1;
    }
}

ProcessReader::ReadResult ProcessReader::read(
    std::uintptr_t address,
    std::size_t size) noexcept {
    ReadResult result;
    result.success = false;
    result.error = ReadError::Unknown;

    if (mem_fd_ < 0) {
        result.error = ReadError::ProcessNotFound;
        result.error_message = "Memory file descriptor not open";
        return result;
    }

    if (size == 0) {
        result.error = ReadError::None;
        result.success = true;
        return result;
    }

    // Pre-allocate buffer
    result.data.resize(size);

    // Use pread to read at offset (thread-safe)
    const ssize_t bytes_read = ::pread(mem_fd_, result.data.data(), size,
        static_cast<off_t>(address));

    if (bytes_read < 0) {
        // Determine error type
        switch (errno) {
            case EIO:
            case ENXIO:
            case EFAULT:
                result.error = ReadError::InvalidAddress;
                result.error_message = "Invalid address: 0x" +
                    std::to_string(address);
                break;
            case EACCES:
            case EPERM:
                result.error = ReadError::PermissionDenied;
                result.error_message = "Permission denied reading address: 0x" +
                    std::to_string(address);
                break;
            default:
                result.error_message = "Read error: " +
                    std::string(std::strerror(errno));
                break;
        }
        result.data.clear();
        return result;
    }

    if (static_cast<std::size_t>(bytes_read) < size) {
        // Partial read - truncate buffer
        result.data.resize(static_cast<std::size_t>(bytes_read));
        result.error = ReadError::BufferTooSmall;
        // Still consider success if we got something
        result.success = (bytes_read > 0);
        return result;
    }

    result.success = true;
    result.error = ReadError::None;
    return result;
}

std::optional<std::uintptr_t> ProcessReader::read_pointer(
    std::uintptr_t address) noexcept {
    // Read pointer-sized value
    std::uintptr_t value = 0;
    const auto result = read(address, sizeof(value));

    if (!result.success || result.data.size() < sizeof(value)) {
        return std::nullopt;
    }

    std::memcpy(&value, result.data.data(), sizeof(value));
    return value;
}

std::optional<std::uintptr_t> ProcessReader::read_got_entry(
    std::uintptr_t got_entry_va) noexcept {
    return read_pointer(got_entry_va);
}

std::vector<std::uintptr_t> ProcessReader::read_got_section(
    std::uintptr_t base_va,
    std::size_t entry_count) noexcept {
    std::vector<std::uintptr_t> values;
    values.reserve(entry_count);

    const std::size_t total_size = entry_count * sizeof(std::uintptr_t);
    auto result = read(base_va, total_size);

    if (!result.success) {
        return values;
    }

    const std::size_t entries_read = result.data.size() / sizeof(std::uintptr_t);
    values.resize(entries_read);

    const std::uintptr_t* data_ptr =
        reinterpret_cast<const std::uintptr_t*>(result.data.data());

    for (std::size_t i = 0; i < entries_read; ++i) {
        values[i] = data_ptr[i];
    }

    return values;
}

bool ProcessReader::refresh_regions() noexcept {
    cached_regions_.reset();

    auto parse_result = MapsParser::parse_ex(pid_);
    if (!parse_result.success) {
        return false;
    }

    cached_regions_ = std::move(parse_result.regions);
    return true;
}

std::unordered_map<std::string, std::uintptr_t>
ProcessReader::get_module_bases() noexcept {
    auto parse_result = MapsParser::parse_ex(pid_);
    if (!parse_result.success) {
        return {};
    }
    return std::move(parse_result.module_bases);
}

std::optional<MemoryRegion> ProcessReader::find_region(
    std::uintptr_t addr) const noexcept {
    if (!cached_regions_) {
        // Lazy load
        auto regions = MapsParser::parse(pid_);
        if (!regions) {
            return std::nullopt;
        }
        cached_regions_ = std::move(regions->regions);
    }

    return MapsParser::find_region(*cached_regions_, addr);
}

std::optional<std::uintptr_t> ProcessReader::find_module_base(
    const std::string& module_name) const noexcept {
    if (!cached_regions_) {
        auto regions = MapsParser::parse(pid_);
        if (!regions) {
            return std::nullopt;
        }
        cached_regions_ = std::move(regions->regions);
    }

    return MapsParser::find_module_base(*cached_regions_, module_name);
}

std::size_t ProcessReader::populate_got_runtime_values(
    SectionInfo& section) noexcept {
    if (!cached_regions_) {
        static_cast<void>(refresh_regions());  // May fail, but try to load
    }

    std::size_t populated = 0;

    for (auto& entry : section.entries) {
        const std::uintptr_t entry_va = section.runtime_address() + entry.offset;

        auto value = read_got_entry(entry_va);
        if (value) {
            entry.runtime_value = *value;

            // Validate: check if the value matches our expected VA
            // This is a basic check - for GOT entries, the value should be
            // a valid function address or pointer
            entry.address_matches = (*value != 0);  // Non-zero means potentially valid
            ++populated;
        }
    }

    return populated;
}

const char* ProcessReader::error_to_string(ReadError error) noexcept {
    switch (error) {
        case ReadError::None:               return "No error";
        case ReadError::PermissionDenied:   return "Permission denied";
        case ReadError::InvalidAddress:     return "Invalid address";
        case ReadError::ProcessNotFound:    return "Process not found";
        case ReadError::BufferTooSmall:     return "Buffer too small";
        case ReadError::Unknown:            return "Unknown error";
        default:                            return "Invalid error code";
    }
}

GOTVerifier::VerificationContext ProcessReader::create_verification_context() const noexcept {
    GOTVerifier::VerificationContext context;
    context.pid = pid_;

    if (cached_regions_) {
        context.regions = *cached_regions_;
    } else {
        // Lazy load regions
        auto parse_result = MapsParser::parse(pid_);
        if (parse_result) {
            context.regions = parse_result->regions;
        }
    }

    // Get module bases
    auto parse_result = MapsParser::parse(pid_);
    if (parse_result) {
        context.module_bases = std::move(parse_result->module_bases);
    }

    return context;
}

GOTVerifier::VerificationResult ProcessReader::verify_got_entry_symbol(
    const GOTEntry& entry,
    const GOTVerifier::VerificationContext& context) const noexcept {
    return GOTVerifier::verify_by_symbol_name(entry, context);
}

GOTVerifier::VerificationResult ProcessReader::verify_got_entry_ld(
    const GOTEntry& entry,
    const std::string& elf_path,
    const GOTVerifier::VerificationContext& context) const noexcept {
    return GOTVerifier::verify_by_ld_simulation(entry, elf_path, context);
}

GOTVerifier::VerificationResult ProcessReader::verify_got_entry(
    GOTEntry& entry,
    const std::string& elf_path,
    const GOTVerifier::VerificationContext& context) const noexcept {

    auto result = GOTVerifier::verify_comprehensive(entry, elf_path, context);

    // Update entry with verification results
    entry.runtime_symbol_name = result.runtime_symbol;
    entry.symbol_name_matches = result.symbol_name_verified;
    entry.expected_address = result.expected_address;
    entry.address_is_hooked = result.is_hooked();

    return result;
}

} // namespace elf::got
