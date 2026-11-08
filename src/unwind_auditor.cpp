#include "vmemscan/unwind_auditor.hpp"

#include <tlhelp32.h>
#include <algorithm>
#include <iomanip>
#include <sstream>

namespace vmemscan {

std::wstring UnwindAuditor::anomaly_type_to_string(UnwindAnomalyType type) {
    switch (type) {
    case UnwindAnomalyType::None:                  return L"None";
    case UnwindAnomalyType::UnwindMetadataMissing: return L"Unwind Metadata Missing in .pdata (Synthetic Stack Frame / Spoofing)";
    case UnwindAnomalyType::UnbackedStackFrame:    return L"Unbacked Stack Return Address (Shellcode Execution)";
    case UnwindAnomalyType::RwxStackFrame:         return L"RWX Page Stack Return Address";
    default:                                       return L"Unknown";
    }
}

bool UnwindAuditor::verify_rva_in_functions(
    uint32_t rva,
    const std::vector<UnwindFunctionEntry>& functions
) {
    if (functions.empty()) {
        return true; // No .pdata table available for this module
    }

    // Binary search over sorted BeginAddress
    auto it = std::upper_bound(functions.begin(), functions.end(), rva,
        [](uint32_t val, const UnwindFunctionEntry& entry) {
            return val < entry.begin_rva;
        });

    if (it != functions.begin()) {
        --it;
        if (rva >= it->begin_rva && rva < it->end_rva) {
            return true;
        }
    }

    return false;
}

static bool is_preceded_by_call(HANDLE hProcess, uint64_t frame) {
    if (frame < 8) return false;
    uint8_t code_buf[8]{0};
    SIZE_T read = 0;
    if (!ReadProcessMemory(hProcess, reinterpret_cast<LPCVOID>(frame - 7), code_buf, 7, &read) || read < 7) {
        return false;
    }

    // 1. 5-byte near relative call: E8 xx xx xx xx (at frame - 5)
    if (code_buf[2] == 0xE8) return true;

    // 2. 6-byte rip-relative call: FF 15 xx xx xx xx (at frame - 6)
    if (code_buf[1] == 0xFF && code_buf[2] == 0x15) return true;

    // 3. 2-byte register call: FF D0-D7 (at frame - 2)
    if (code_buf[5] == 0xFF && (code_buf[6] & 0xF8) == 0xD0) return true;

    // 4. 3-byte r8-r15 register call: 41 FF D0-D7 (at frame - 3)
    if (code_buf[4] == 0x41 && code_buf[5] == 0xFF && (code_buf[6] & 0xF8) == 0xD0) return true;

    // 5. 2-byte indirect pointer call: FF 10-17 (at frame - 2)
    if (code_buf[5] == 0xFF && (code_buf[6] & 0xF8) == 0x10) return true;

    // 6. 3-byte indirect call with disp8: FF 50-57 xx (at frame - 3)
    if (code_buf[4] == 0xFF && (code_buf[5] & 0xF8) == 0x50) return true;

    // 7. 4-byte SIB call: FF 54 24 xx (at frame - 4)
    if (code_buf[3] == 0xFF && code_buf[4] == 0x54 && code_buf[5] == 0x24) return true;

    return false;
}

std::vector<UnwindAnomaly> UnwindAuditor::evaluate_thread_frames(
    uint32_t thread_id,
    const std::vector<uint64_t>& stack_frames,
    uint64_t module_base,
    uint64_t module_size,
    const std::wstring& module_name,
    const std::vector<UnwindFunctionEntry>& module_functions,
    const std::vector<MemoryRegion>& regions
) {
    std::vector<UnwindAnomaly> anomalies;

    for (uint64_t frame : stack_frames) {
        if (frame == 0) {
            continue;
        }

        // Find memory region covering this frame address
        const MemoryRegion* frame_region = nullptr;
        for (const auto& reg : regions) {
            if (reg.base_address <= frame && frame < (reg.base_address + reg.region_size)) {
                frame_region = &reg;
                break;
            }
        }

        if (frame_region) {
            bool is_exec = frame_region->is_executable || ((frame_region->protect & 0xF0) != 0);
            if (!is_exec) {
                continue; // Data pointer on stack, skip
            }
        }

        // Check if frame resides within the target module
        if (module_base != 0 && frame >= module_base && frame < (module_base + module_size)) {
            uint32_t rva = static_cast<uint32_t>(frame - module_base);

            // If module has .pdata and frame is not inside any registered function
            if (!module_functions.empty() && !verify_rva_in_functions(rva, module_functions)) {
                UnwindAnomaly a{};
                a.thread_id = thread_id;
                a.frame_address = frame;
                a.module_name = module_name;
                a.module_base = module_base;
                a.rva = rva;
                a.type = UnwindAnomalyType::UnwindMetadataMissing;
                a.is_critical = true;

                std::wostringstream oss;
                oss << L"Stack frame 0x" << std::hex << frame << L" (RVA +0x" << rva
                    << L") in module " << module_name
                    << L" is not registered in .pdata Exception Directory (fabricated frame or code cave)";
                a.details = oss.str();
                anomalies.push_back(a);
                continue;
            }
        }

        // Check if frame resides in unbacked private memory
        for (const auto& reg : regions) {
            if (reg.base_address <= frame && frame < (reg.base_address + reg.region_size)) {
                if (reg.is_rwx) {
                    UnwindAnomaly a{};
                    a.thread_id = thread_id;
                    a.frame_address = frame;
                    a.type = UnwindAnomalyType::RwxStackFrame;
                    a.is_critical = true;

                    std::wostringstream oss;
                    oss << L"Stack frame 0x" << std::hex << frame
                        << L" returns into PAGE_EXECUTE_READWRITE memory";
                    a.details = oss.str();
                    anomalies.push_back(a);
                } else if (reg.is_unbacked_executable) {
                    UnwindAnomaly a{};
                    a.thread_id = thread_id;
                    a.frame_address = frame;
                    a.type = UnwindAnomalyType::UnbackedStackFrame;
                    a.is_critical = true;

                    std::wostringstream oss;
                    oss << L"Stack frame 0x" << std::hex << frame
                        << L" returns into unbacked private executable memory";
                    a.details = oss.str();
                    anomalies.push_back(a);
                }
                break;
            }
        }
    }

    return anomalies;
}

#pragma pack(push, 1)
struct VmemRuntimeFunctionX64 {
    DWORD BeginAddress;
    DWORD EndAddress;
    DWORD UnwindData;
};

struct VmemRuntimeFunctionArm64 {
    DWORD BeginAddress;
    DWORD UnwindData;
};
#pragma pack(pop)

static bool read_module_info(
    HANDLE hProcess,
    uint64_t module_base,
    uint64_t& size_of_image,
    std::vector<UnwindFunctionEntry>& entries
) {
    size_of_image = 0;
    entries.clear();
    if (module_base == 0) return false;

    IMAGE_DOS_HEADER dos{};
    SIZE_T read = 0;
    if (!ReadProcessMemory(hProcess, reinterpret_cast<LPCVOID>(module_base), &dos, sizeof(dos), &read) ||
        dos.e_magic != IMAGE_DOS_SIGNATURE) {
        return false;
    }

    IMAGE_NT_HEADERS64 nth{};
    if (!ReadProcessMemory(hProcess, reinterpret_cast<LPCVOID>(module_base + dos.e_lfanew), &nth, sizeof(nth), &read) ||
        nth.Signature != IMAGE_NT_SIGNATURE) {
        return false;
    }

    size_of_image = nth.OptionalHeader.SizeOfImage;

    const auto& exc_dir = nth.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION];
    if (exc_dir.VirtualAddress == 0) {
        return true;
    }

    if (nth.FileHeader.Machine == IMAGE_FILE_MACHINE_ARM64) {
        if (exc_dir.Size < sizeof(VmemRuntimeFunctionArm64)) return true;
        size_t count = exc_dir.Size / sizeof(VmemRuntimeFunctionArm64);
        if (count > 500000) count = 500000;

        std::vector<VmemRuntimeFunctionArm64> rf_table(count);
        if (!ReadProcessMemory(hProcess, reinterpret_cast<LPCVOID>(module_base + exc_dir.VirtualAddress),
                               rf_table.data(), count * sizeof(VmemRuntimeFunctionArm64), &read)) {
            return true;
        }

        entries.reserve(count);
        for (size_t i = 0; i < count; ++i) {
            UnwindFunctionEntry fe{};
            fe.begin_rva = rf_table[i].BeginAddress;
            DWORD flag = rf_table[i].UnwindData & 0x3;
            DWORD fn_len_instr = (rf_table[i].UnwindData >> 2) & 0x7FF;
            if (flag != 0 && fn_len_instr > 0) {
                fe.end_rva = fe.begin_rva + (fn_len_instr * 4);
            } else if (i + 1 < count && rf_table[i + 1].BeginAddress > fe.begin_rva) {
                fe.end_rva = rf_table[i + 1].BeginAddress;
            } else {
                fe.end_rva = fe.begin_rva + 4;
            }
            if (fe.begin_rva < fe.end_rva) {
                entries.push_back(fe);
            }
        }
    } else {
        // AMD64 / x64 default
        if (exc_dir.Size < sizeof(VmemRuntimeFunctionX64)) return true;
        size_t count = exc_dir.Size / sizeof(VmemRuntimeFunctionX64);
        if (count > 500000) count = 500000;

        std::vector<VmemRuntimeFunctionX64> rf_table(count);
        if (!ReadProcessMemory(hProcess, reinterpret_cast<LPCVOID>(module_base + exc_dir.VirtualAddress),
                               rf_table.data(), count * sizeof(VmemRuntimeFunctionX64), &read)) {
            return true;
        }

        entries.reserve(count);
        for (size_t i = 0; i < count; ++i) {
            UnwindFunctionEntry fe{};
            fe.begin_rva = rf_table[i].BeginAddress;
            fe.end_rva = rf_table[i].EndAddress;
            if (fe.begin_rva < fe.end_rva) {
                entries.push_back(fe);
            }
        }
    }

    std::sort(entries.begin(), entries.end(),
        [](const UnwindFunctionEntry& a, const UnwindFunctionEntry& b) {
            return a.begin_rva < b.begin_rva;
        });

    return true;
}

UnwindAuditReport UnwindAuditor::audit_process_unwind(
    HANDLE hProcess,
    uint32_t pid,
    const std::wstring& process_name,
    const std::vector<MemoryRegion>& regions
) {
    UnwindAuditReport rep{};
    rep.pid = pid;
    rep.process_name = process_name;

    if (!hProcess) {
        return rep;
    }

    // Cache module .pdata tables and real virtual size
    struct CachedModule {
        uint64_t base_address = 0;
        uint64_t size_of_image = 0;
        std::wstring name;
        std::vector<UnwindFunctionEntry> functions;
    };
    std::vector<CachedModule> cached_modules;

    for (const auto& reg : regions) {
        if (reg.type == MEM_IMAGE && reg.state == MEM_COMMIT && reg.base_address == reg.allocation_base && reg.base_address != 0) {
            CachedModule cm{};
            cm.base_address = reg.base_address;
            cm.name = reg.mapped_file.empty() ? L"<module>" : reg.mapped_file;
            if (read_module_info(hProcess, reg.base_address, cm.size_of_image, cm.functions)) {
                if (cm.size_of_image == 0) {
                    cm.size_of_image = reg.region_size;
                }
                cached_modules.push_back(std::move(cm));
            }
        }
    }

    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (hSnap == INVALID_HANDLE_VALUE) {
        return rep;
    }

    THREADENTRY32 te{};
    te.dwSize = sizeof(te);

    if (Thread32First(hSnap, &te)) {
        do {
            if (te.th32OwnerProcessID != pid) {
                continue;
            }

            ++rep.threads_inspected;

            HANDLE hThread = OpenThread(THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT | THREAD_QUERY_INFORMATION, FALSE, te.th32ThreadID);
            if (!hThread) {
                continue;
            }

            bool is_current = (te.th32ThreadID == GetCurrentThreadId());
            if (!is_current) {
                SuspendThread(hThread);
            }

            CONTEXT ctx{};
            ctx.ContextFlags = CONTEXT_CONTROL;
            if (GetThreadContext(hThread, &ctx)) {
                #if defined(_M_AMD64) || defined(__x86_64__)
                uint64_t rsp = ctx.Rsp;
                #elif defined(_M_ARM64) || defined(__aarch64__)
                uint64_t rsp = ctx.Sp;
                #else
                uint64_t rsp = 0;
                #endif

                if (rsp != 0) {
                    // Read top 64 pointer slots from thread stack
                    uint64_t stack_slots[64]{0};
                    SIZE_T read = 0;
                    if (ReadProcessMemory(hProcess, reinterpret_cast<LPCVOID>(rsp), stack_slots, sizeof(stack_slots), &read)) {
                        size_t num_slots = read / sizeof(uint64_t);
                        rep.frames_evaluated += num_slots;

                        for (size_t i = 0; i < num_slots; ++i) {
                            uint64_t frame = stack_slots[i];
                            if (frame == 0) continue;

                            // Find memory region covering this frame address
                            const MemoryRegion* frame_region = nullptr;
                            for (const auto& reg : regions) {
                                if (reg.base_address <= frame && frame < (reg.base_address + reg.region_size)) {
                                    frame_region = &reg;
                                    break;
                                }
                            }

                            if (!frame_region) continue;

                            // Return addresses must reside in executable memory.
                            bool is_exec = frame_region->is_executable || ((frame_region->protect & 0xF0) != 0);
                            if (!is_exec) {
                                continue;
                            }

                            // Verify that this address was actually placed by a CALL instruction
                            if (!is_preceded_by_call(hProcess, frame)) {
                                continue; // Stored function pointer or non-return address
                            }

                            // Direct match against cached modules
                            const CachedModule* matched_mod = nullptr;
                            for (const auto& cm : cached_modules) {
                                if (frame >= cm.base_address && frame < (cm.base_address + cm.size_of_image)) {
                                    matched_mod = &cm;
                                    break;
                                }
                            }

                            if (matched_mod) {
                                if (!matched_mod->functions.empty()) {
                                    uint32_t rva = static_cast<uint32_t>(frame - matched_mod->base_address);
                                    if (!verify_rva_in_functions(rva, matched_mod->functions)) {
                                        UnwindAnomaly a{};
                                        a.thread_id = te.th32ThreadID;
                                        a.frame_address = frame;
                                        a.module_name = matched_mod->name;
                                        a.module_base = matched_mod->base_address;
                                        a.rva = rva;
                                        a.type = UnwindAnomalyType::UnwindMetadataMissing;
                                        a.is_critical = true;

                                        std::wostringstream oss;
                                        oss << L"Stack frame 0x" << std::hex << frame << L" (RVA +0x" << rva
                                            << L") in module " << matched_mod->name
                                            << L" is not registered in .pdata Exception Directory (fabricated frame or code cave)";
                                        a.details = oss.str();
                                        rep.anomalies.push_back(std::move(a));
                                    }
                                }
                            } else {
                                // Frame is outside all modules: check if in unbacked / RWX memory
                                if (frame_region->is_rwx) {
                                    UnwindAnomaly a{};
                                    a.thread_id = te.th32ThreadID;
                                    a.frame_address = frame;
                                    a.type = UnwindAnomalyType::RwxStackFrame;
                                    a.is_critical = true;

                                    std::wostringstream oss;
                                    oss << L"Stack frame 0x" << std::hex << frame
                                        << L" returns into PAGE_EXECUTE_READWRITE memory";
                                    a.details = oss.str();
                                    rep.anomalies.push_back(std::move(a));
                                } else if (frame_region->is_unbacked_executable) {
                                    UnwindAnomaly a{};
                                    a.thread_id = te.th32ThreadID;
                                    a.frame_address = frame;
                                    a.type = UnwindAnomalyType::UnbackedStackFrame;
                                    a.is_critical = true;

                                    std::wostringstream oss;
                                    oss << L"Stack frame 0x" << std::hex << frame
                                        << L" returns into unbacked private executable memory";
                                    a.details = oss.str();
                                    rep.anomalies.push_back(std::move(a));
                                }
                            }
                        }
                    }
                }
            }

            if (!is_current) {
                ResumeThread(hThread);
            }
            CloseHandle(hThread);

        } while (Thread32Next(hSnap, &te));
    }

    CloseHandle(hSnap);

    // Remove duplicates if any
    std::sort(rep.anomalies.begin(), rep.anomalies.end(),
        [](const UnwindAnomaly& a, const UnwindAnomaly& b) {
            if (a.thread_id != b.thread_id) return a.thread_id < b.thread_id;
            return a.frame_address < b.frame_address;
        });
    rep.anomalies.erase(std::unique(rep.anomalies.begin(), rep.anomalies.end(),
        [](const UnwindAnomaly& a, const UnwindAnomaly& b) {
            return a.thread_id == b.thread_id && a.frame_address == b.frame_address;
        }), rep.anomalies.end());

    rep.anomalous_frames_count = rep.anomalies.size();
    return rep;
}

} // namespace vmemscan
