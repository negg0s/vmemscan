#pragma once

#include "vmemscan/common.hpp"

namespace vmemscan {

class PrivilegeManager {
public:
    static bool is_elevated_admin();
    static bool enable_debug_privilege();
    static bool enable_privilege(const wchar_t* privilege_name);
};

} // namespace vmemscan
