#include "vmemscan/mitigations_auditor.hpp"

namespace vmemscan {

ProcessMitigationsReport MitigationsAuditor::audit_process_mitigations(
    HANDLE hProcess,
    uint32_t pid,
    const std::wstring& process_name
) {
    ProcessMitigationsReport rep{};
    rep.pid = pid;
    rep.process_name = process_name;

    if (!hProcess || pid == 0) {
        return rep;
    }

    // 1. Data Execution Prevention (DEP)
    PROCESS_MITIGATION_DEP_POLICY dep{};
    if (GetProcessMitigationPolicy(hProcess, ProcessDEPPolicy, &dep, sizeof(dep))) {
        rep.dep_enabled = dep.Enable != 0;
        MitigationEntry e{};
        e.policy_name = L"Data Execution Prevention (DEP)";
        e.is_enforced = rep.dep_enabled;
        e.status_text = rep.dep_enabled ? L"Enforced (Permanent: " + std::wstring(dep.Permanent ? L"True" : L"False") + L")" : L"Disabled";
        e.is_security_relevant = true;
        e.description = L"Hardware-enforced execution prevention on non-executable memory pages (NX/XD bit)";
        rep.policies.push_back(std::move(e));
    }

    // 2. Address Space Layout Randomization (ASLR)
    PROCESS_MITIGATION_ASLR_POLICY aslr{};
    if (GetProcessMitigationPolicy(hProcess, ProcessASLRPolicy, &aslr, sizeof(aslr))) {
        rep.aslr_bottom_up = aslr.EnableBottomUpRandomization != 0;
        rep.aslr_high_entropy = aslr.EnableHighEntropy != 0;
        MitigationEntry e{};
        e.policy_name = L"Address Space Layout Randomization (ASLR)";
        e.is_enforced = rep.aslr_bottom_up;
        std::wstring status = L"BottomUp: " + std::wstring(rep.aslr_bottom_up ? L"True" : L"False") +
                              L", HighEntropy: " + std::wstring(rep.aslr_high_entropy ? L"True" : L"False") +
                              L", ForceRelocate: " + std::wstring(aslr.EnableForceRelocateImages ? L"True" : L"False");
        e.status_text = status;
        e.is_security_relevant = true;
        e.description = L"Randomizes base addresses of stack, heap, and loaded modules to obstruct ROP";
        rep.policies.push_back(std::move(e));
    }

    // 3. Dynamic Code Policy / Arbitrary Code Guard (ACG)
    PROCESS_MITIGATION_DYNAMIC_CODE_POLICY dynamic_code{};
    if (GetProcessMitigationPolicy(hProcess, ProcessDynamicCodePolicy, &dynamic_code, sizeof(dynamic_code))) {
        rep.acg_prohibit_dynamic_code = dynamic_code.ProhibitDynamicCode != 0;
        MitigationEntry e{};
        e.policy_name = L"Arbitrary Code Guard (ACG)";
        e.is_enforced = rep.acg_prohibit_dynamic_code;
        e.status_text = rep.acg_prohibit_dynamic_code ? L"Enforced (Dynamic Code Blocked)" : L"Disabled (Dynamic Executable Pages Allowed)";
        e.is_security_relevant = true;
        e.description = L"Prevents generation of dynamic code and altering existing code pages to writable (blocks VirtualAlloc/VirtualProtect RWX abuse)";
        rep.policies.push_back(std::move(e));
    }

    // 4. Control Flow Guard (CFG)
    PROCESS_MITIGATION_CONTROL_FLOW_GUARD_POLICY cfg{};
    if (GetProcessMitigationPolicy(hProcess, ProcessControlFlowGuardPolicy, &cfg, sizeof(cfg))) {
        rep.cfg_enabled = cfg.EnableControlFlowGuard != 0;
        MitigationEntry e{};
        e.policy_name = L"Control Flow Guard (CFG)";
        e.is_enforced = rep.cfg_enabled;
        e.status_text = rep.cfg_enabled ? L"Enforced (ExportSuppression: " + std::wstring(cfg.EnableExportSuppression ? L"True" : L"False") + L")" : L"Disabled";
        e.is_security_relevant = true;
        e.description = L"Validates indirect call and jump targets against compiler-generated bitmap to stop control flow hijacking";
        rep.policies.push_back(std::move(e));
    }

    // 5. Binary Signature Policy
    PROCESS_MITIGATION_BINARY_SIGNATURE_POLICY sig{};
    if (GetProcessMitigationPolicy(hProcess, ProcessSignaturePolicy, &sig, sizeof(sig))) {
        rep.msft_signed_only = sig.MicrosoftSignedOnly != 0;
        MitigationEntry e{};
        e.policy_name = L"Binary Signature Enforcement";
        e.is_enforced = rep.msft_signed_only;
        e.status_text = rep.msft_signed_only ? L"Microsoft Binaries Only" : (sig.StoreSignedOnly ? L"Store Signed Only" : L"Standard Validation");
        e.is_security_relevant = true;
        e.description = L"Restricts module loading to Microsoft-signed or Windows Store-signed binaries";
        rep.policies.push_back(std::move(e));
    }

    // 6. Image Load Policy
    PROCESS_MITIGATION_IMAGE_LOAD_POLICY img{};
    if (GetProcessMitigationPolicy(hProcess, ProcessImageLoadPolicy, &img, sizeof(img))) {
        rep.no_remote_images = img.NoRemoteImages != 0;
        MitigationEntry e{};
        e.policy_name = L"Remote Image Load Policy";
        e.is_enforced = rep.no_remote_images;
        e.status_text = rep.no_remote_images ? L"Enforced (Remote UNC Loading Blocked)" : L"Permitted";
        e.is_security_relevant = true;
        e.description = L"Blocks loading of executable DLL images from remote network or UNC shares";
        rep.policies.push_back(std::move(e));
    }

    // 7. Child Process Policy
    PROCESS_MITIGATION_CHILD_PROCESS_POLICY child{};
    if (GetProcessMitigationPolicy(hProcess, ProcessChildProcessPolicy, &child, sizeof(child))) {
        rep.no_child_processes = child.NoChildProcessCreation != 0;
        MitigationEntry e{};
        e.policy_name = L"Child Process Creation Restriction";
        e.is_enforced = rep.no_child_processes;
        e.status_text = rep.no_child_processes ? L"Blocked (Child Process Spawn Prohibited)" : L"Permitted";
        e.is_security_relevant = true;
        e.description = L"Prohibits target process from spawning child subprocesses";
        rep.policies.push_back(std::move(e));
    }

    // 8. Strict Handle Checking Policy
    PROCESS_MITIGATION_STRICT_HANDLE_CHECK_POLICY handle{};
    if (GetProcessMitigationPolicy(hProcess, ProcessStrictHandleCheckPolicy, &handle, sizeof(handle))) {
        rep.strict_handle_checks = handle.RaiseExceptionOnInvalidHandleReference != 0;
        MitigationEntry e{};
        e.policy_name = L"Strict Handle Checking";
        e.is_enforced = rep.strict_handle_checks;
        e.status_text = rep.strict_handle_checks ? L"Enforced (Exception on Invalid Handle)" : L"Standard";
        e.is_security_relevant = true;
        e.description = L"Raises immediate STATUS_HANDLE_NOT_CLOSABLE or exception on invalid handle references";
        rep.policies.push_back(std::move(e));
    }

    return rep;
}

} // namespace vmemscan
