#include "vmemscan/ioc_extractor.hpp"

#include <algorithm>
#include <regex>

namespace vmemscan {

std::wstring IocExtractor::ioc_type_to_string(IocType type) {
    switch (type) {
    case IocType::Url:           return L"URL / Web Endpoint";
    case IocType::NamedPipe:     return L"Named Pipe (C2 Transport)";
    case IocType::IpAddress:     return L"IPv4 Address";
    case IocType::SystemCommand: return L"System Command / Lolbin";
    case IocType::FilePath:      return L"File System Path";
    case IocType::GenericString: return L"String Artifact";
    default:                     return L"Unknown";
    }
}

static IocType classify_string(const std::wstring& str) {
    std::wstring lower = str;
    for (auto& c : lower) c = static_cast<wchar_t>(towlower(c));

    if (lower.rfind(L"http://", 0) == 0 || lower.rfind(L"https://", 0) == 0) {
        return IocType::Url;
    }
    if (lower.find(L"\\pipe\\") != std::wstring::npos || lower.find(L"\\\\.\\pipe\\") != std::wstring::npos) {
        return IocType::NamedPipe;
    }
    if (lower.find(L"powershell") != std::wstring::npos ||
        lower.find(L"cmd.exe") != std::wstring::npos ||
        lower.find(L"certutil") != std::wstring::npos ||
        lower.find(L"rundll32") != std::wstring::npos ||
        lower.find(L"mshta") != std::wstring::npos ||
        lower.find(L"vssadmin") != std::wstring::npos) {
        return IocType::SystemCommand;
    }
    if ((str.size() >= 3 && iswalpha(str[0]) && str[1] == L':' && str[2] == L'\\') ||
        lower.rfind(L"\\\\", 0) == 0) {
        return IocType::FilePath;
    }

    // Basic IPv4 check
    static const std::wregex ip_regex(LR"(^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$)");
    if (std::regex_match(str, ip_regex)) {
        return IocType::IpAddress;
    }

    return IocType::GenericString;
}

std::vector<IocArtifact> IocExtractor::scan_buffer_iocs(
    const uint8_t* data,
    size_t size,
    uint64_t base_address,
    size_t min_len
) {
    std::vector<IocArtifact> artifacts;
    if (!data || size < min_len) {
        return artifacts;
    }

    // 1. Scan ASCII string tokens
    size_t start = 0;
    bool in_string = false;

    for (size_t i = 0; i <= size; ++i) {
        uint8_t c = (i < size) ? data[i] : 0;
        if (c > 0x20 && c <= 0x7E) {
            if (!in_string) {
                in_string = true;
                start = i;
            }
        } else {
            if (in_string) {
                size_t len = i - start;
                if (len >= min_len && len <= 1024) {
                    std::string s(reinterpret_cast<const char*>(&data[start]), len);
                    // Trim trailing punctuation like '"', '\'', ';', ','
                    while (!s.empty() && (s.back() == '"' || s.back() == '\'' || s.back() == ';' || s.back() == ',')) {
                        s.pop_back();
                    }
                    if (s.size() >= min_len) {
                        std::wstring ws(s.begin(), s.end());
                        IocType t = classify_string(ws);
                        if (t != IocType::GenericString) {
                            IocArtifact art{};
                            art.type = t;
                            art.value = std::move(ws);
                            art.virtual_address = base_address + start;
                            art.is_unicode = false;
                            artifacts.push_back(std::move(art));
                        }
                    }
                }
                in_string = false;
            }
        }
    }

    // 2. Scan UTF-16LE string tokens
    size_t u_start = 0;
    bool in_u_string = false;

    for (size_t i = 0; i + 1 <= size; i += 2) {
        bool is_valid_char = false;
        uint8_t c1 = 0;
        if (i + 1 < size) {
            c1 = data[i];
            uint8_t c2 = data[i + 1];
            if (c2 == 0x00 && c1 > 0x20 && c1 <= 0x7E) {
                is_valid_char = true;
            }
        }

        if (is_valid_char) {
            if (!in_u_string) {
                in_u_string = true;
                u_start = i;
            }
        } else {
            if (in_u_string) {
                size_t byte_len = i - u_start;
                size_t char_len = byte_len / 2;
                if (char_len >= min_len && char_len <= 1024) {
                    std::wstring ws(reinterpret_cast<const wchar_t*>(&data[u_start]), char_len);
                    while (!ws.empty() && (ws.back() == L'"' || ws.back() == L'\'' || ws.back() == L';' || ws.back() == L',')) {
                        ws.pop_back();
                    }
                    if (ws.size() >= min_len) {
                        IocType t = classify_string(ws);
                        if (t != IocType::GenericString) {
                            IocArtifact art{};
                            art.type = t;
                            art.value = std::move(ws);
                            art.virtual_address = base_address + u_start;
                            art.is_unicode = true;
                            artifacts.push_back(std::move(art));
                        }
                    }
                }
                in_u_string = false;
            }
        }
    }

    return artifacts;
}

IocReport IocExtractor::extract_iocs_from_memory(
    HANDLE hProcess,
    uint32_t pid,
    const std::wstring& process_name,
    uint64_t base_address,
    uint64_t size_to_scan,
    size_t min_len
) {
    IocReport rep{};
    rep.pid = pid;
    rep.process_name = process_name;
    rep.target_address = base_address;

    if (!hProcess || size_to_scan == 0) {
        return rep;
    }

    const size_t chunk_size = 65536;
    std::vector<uint8_t> buffer(chunk_size);
    uint64_t offset = 0;

    while (offset < size_to_scan) {
        const size_t to_read = static_cast<size_t>((std::min)(static_cast<uint64_t>(chunk_size), size_to_scan - offset));
        SIZE_T read = 0;

        if (ReadProcessMemory(hProcess, reinterpret_cast<LPCVOID>(base_address + offset), buffer.data(), to_read, &read) && read >= min_len) {
            auto found = scan_buffer_iocs(buffer.data(), read, base_address + offset, min_len);
            for (auto& f : found) {
                rep.artifacts.push_back(std::move(f));
            }
        }

        offset += to_read;
    }

    rep.total_strings_found = rep.artifacts.size();
    return rep;
}

} // namespace vmemscan
