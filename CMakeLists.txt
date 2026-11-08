cmake_minimum_required(VERSION 3.20)

project(vmemscan
    VERSION 0.5.0
    LANGUAGES CXX
)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Static CRT for all configurations
set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")

add_compile_definitions(UNICODE _UNICODE)

if(MSVC)
    string(TOLOWER "${CMAKE_GENERATOR_PLATFORM}_${CMAKE_SYSTEM_PROCESSOR}_${CMAKE_VS_PLATFORM_NAME}" _arch_lower)
    if(_arch_lower MATCHES "arm64")
        set(IS_ARM64_TARGET TRUE)
    else()
        set(IS_ARM64_TARGET FALSE)
    endif()

    add_compile_options(
        /W4
        /WX
        /permissive-
        /utf-8
        /EHsc
        /GS
        /guard:cf
        $<$<CONFIG:Release>:/Qspectre>
    )

    add_link_options(
        /GUARD:CF
        /DYNAMICBASE
        /HIGHENTROPYVA
        /Brepro
    )

    if(NOT IS_ARM64_TARGET)
        add_link_options(/CETCOMPAT)
    endif()
endif()

# Core static library
add_library(vmemscan_core STATIC
    include/vmemscan/c2_detector.hpp
    include/vmemscan/common.hpp
    include/vmemscan/entropy_calculator.hpp
    include/vmemscan/formatter.hpp
    include/vmemscan/hook_detector.hpp
    include/vmemscan/hollowing_detector.hpp
    include/vmemscan/iat_hook_detector.hpp
    include/vmemscan/injection_detector.hpp
    include/vmemscan/ioc_extractor.hpp
    include/vmemscan/memory_dumper.hpp
    include/vmemscan/memory_scanner.hpp
    include/vmemscan/module_auditor.hpp
    include/vmemscan/nt_defs.hpp
    include/vmemscan/patch_detector.hpp
    include/vmemscan/pattern_scanner.hpp
    include/vmemscan/peb_auditor.hpp
    include/vmemscan/privileges.hpp
    include/vmemscan/process_snapshot.hpp
    include/vmemscan/risk_scorer.hpp
    include/vmemscan/snapshot_differ.hpp
    include/vmemscan/syscall_auditor.hpp
    include/vmemscan/thread_analyzer.hpp

    src/c2_detector.cpp
    src/entropy_calculator.cpp
    src/formatter.cpp
    src/hook_detector.cpp
    src/hollowing_detector.cpp
    src/iat_hook_detector.cpp
    src/injection_detector.cpp
    src/ioc_extractor.cpp
    src/memory_dumper.cpp
    src/memory_scanner.cpp
    src/module_auditor.cpp
    src/patch_detector.cpp
    src/pattern_scanner.cpp
    src/peb_auditor.cpp
    src/privileges.cpp
    src/process_snapshot.cpp
    src/risk_scorer.cpp
    src/snapshot_differ.cpp
    src/syscall_auditor.cpp
    src/thread_analyzer.cpp
)

target_include_directories(vmemscan_core PUBLIC include)
target_link_libraries(vmemscan_core PUBLIC advapi32 psapi)

# Main CLI executable
add_executable(vmemscan
    src/main.cpp
)

target_link_libraries(vmemscan PRIVATE vmemscan_core)

# Tests
enable_testing()

add_executable(vmemscan_tests
    tests/test_main.cpp
)

target_link_libraries(vmemscan_tests PRIVATE vmemscan_core)

add_test(NAME unit_tests COMMAND vmemscan_tests)
