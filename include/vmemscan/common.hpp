#pragma once

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>

#include <cstdint>
#include <string>
#include <vector>

namespace vmemscan {

struct Error {
    uint32_t code{0};
    std::wstring message;

    Error() = default;
    Error(uint32_t c, std::wstring m) : code(c), message(std::move(m)) {}

    std::wstring to_string() const {
        return message + L" (Win32 error: " + std::to_wstring(code) + L")";
    }
};

template <typename T>
class Result {
public:
    Result(T val) : has_value_(true), value_(std::move(val)) {}
    Result(Error err) : has_value_(false), error_(std::move(err)) {}

    bool has_value() const { return has_value_; }
    explicit operator bool() const { return has_value_; }

    const T& value() const { return value_; }
    T& value() { return value_; }

    const Error& error() const { return error_; }

private:
    bool has_value_{false};
    T value_{};
    Error error_{};
};

struct ProcessInfo {
    uint32_t pid{0};
    uint32_t parent_pid{0};
    std::wstring name;
    std::wstring path;
    uint32_t session_id{0};
    bool is_64bit{true};
    bool is_elevated{false};
    uint64_t working_set_bytes{0};
    uint64_t commit_bytes{0};
    uint32_t thread_count{0};
};

struct MemoryRegion {
    uint64_t base_address{0};
    uint64_t allocation_base{0};
    uint64_t region_size{0};
    uint32_t state{0};
    uint32_t protect{0};
    uint32_t alloc_protect{0};
    uint32_t type{0};
    std::wstring mapped_file;
    bool is_executable{false};
    bool is_writable{false};
    bool is_unbacked_executable{false};
    bool is_rwx{false};
};

struct ProcessMemorySummary {
    uint32_t pid{0};
    std::wstring process_name;
    size_t total_regions{0};
    size_t committed_regions{0};
    uint64_t total_committed_bytes{0};
    uint64_t total_private_bytes{0};
    uint64_t total_mapped_bytes{0};
    uint64_t total_image_bytes{0};
    uint64_t executable_bytes{0};
    uint64_t unbacked_executable_bytes{0};
    uint64_t rwx_bytes{0};
    size_t unbacked_executable_regions_count{0};
    size_t rwx_regions_count{0};
};

} // namespace vmemscan
