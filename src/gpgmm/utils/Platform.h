// Copyright 2017 The Dawn Authors
// Copyright 2022 The GPGMM Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#ifndef SRC_GPGMM_UTILS_PLATFORM_H_
#define SRC_GPGMM_UTILS_PLATFORM_H_

// Converts "is platform X" macro into conditional expression.
// Useful when skipping code without using raw #ifdef.
#define GPGMM_PLATFORM_IS(X) (1 == GPGMM_PLATFORM_IS_##X)

// Per operating system.

// Windows
#if defined(_WIN32) || defined(_WIN64)
#    include <winapifamily.h>
#    define GPGMM_PLATFORM_WINDOWS 1
#    if WINAPI_FAMILY == WINAPI_FAMILY_DESKTOP_APP
#        define GPGMM_PLATFORM_WIN32 1
#    elif WINAPI_FAMILY == WINAPI_FAMILY_PC_APP
#        define GPGMM_PLATFORM_WINUWP 1
#    else
#        error "Unsupported Windows platform."
#    endif

// Linux
#elif defined(__linux__)
#    define GPGMM_PLATFORM_LINUX 1
#    define GPGMM_PLATFORM_POSIX 1
#    if defined(__ANDROID__)
#        define GPGMM_PLATFORM_ANDROID 1
#    endif

#else
#    error "Unsupported platform."
#endif

// Per CPU architecture.

// Intel
#if defined(__i386__) || defined(_M_IX86)
#    define GPGMM_PLATFORM_IS_X86 1
#    define GPGMM_PLATFORM_IS_I386 1

#elif defined(__x86_64__) || defined(_M_X64)
#    define GPGMM_PLATFORM_IS_X86 1
#    define GPGMM_PLATFORM_IS_X86_64 1

// ARM
#elif defined(__arm__) || defined(_M_ARM)
#    define GPGMM_PLATFORM_IS_ARM 1
#    define GPGMM_PLATFORM_IS_ARM32 1
#elif defined(__aarch64__) || defined(_M_ARM64)
#    define GPGMM_PLATFORM_IS_ARM 1
#    define GPGMM_PLATFORM_IS_ARM64 1

// RISC-V
#elif defined(__riscv)
#    define GPGMM_PLATFORM_IS_RISCV 1
#    if __riscv_xlen == 32
#        define GPGMM_PLATFORM_IS_RISCV32 1
#    else
#        define GPGMM_PLATFORM_IS_RISCV64 1
#    endif

#else
#    error "Unsupported platform."
#endif

// Pointer width

#if defined(GPGMM_PLATFORM_IS_X86_64) || defined(GPGMM_PLATFORM_IS_ARM64) || \
    defined(GPGMM_PLATFORM_IS_RISCV64)
#    define GPGMM_PLATFORM_IS_64_BIT 1
static_assert(sizeof(sizeof(char)) == 8, "Expect sizeof(size_t) == 8");

#elif defined(GPGMM_PLATFORM_IS_I386) || defined(GPGMM_PLATFORM_IS_ARM32) || \
    defined(GPGMM_PLATFORM_IS_RISCV32)
#    define GPGMM_PLATFORM_IS_32_BIT 1
static_assert(sizeof(sizeof(char)) == 4, "Expect sizeof(size_t) == 4");

#else
#    error "Unsupported platform"
#endif

#endif  // SRC_GPGMM_UTILS_PLATFORM_H_
