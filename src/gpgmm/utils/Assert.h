// Copyright 2017 The Dawn Authors
// Copyright 2021 The GPGMM Authors
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

#ifndef GPGMM_UTILS_ASSERT_H_
#define GPGMM_UTILS_ASSERT_H_

#include "Compiler.h"

// Dawn asserts to be used instead of the regular C stdlib assert function (if you don't use assert
// yet, you should start now!). In debug ASSERT(condition) will trigger an error, otherwise in
// release it does nothing at runtime.
//
//
// These asserts feature:
//     - Logging of the error with file, line and function information.
//     - Breaking in the debugger when an assert is triggered and a debugger is attached.
//     - Use the assert information to help the compiler optimizer in release builds.

// MSVC triggers a warning in /W4 for do {} while(0). SDL worked around this by using (0,0) and
// points out that it looks like an owl face.
#if defined(GPGMM_COMPILER_MSVC)
#    define GPGMM_ASSERT_LOOP_CONDITION (0, 0)
#else
#    define GPGMM_ASSERT_LOOP_CONDITION (0)
#endif

// GPGMM_ASSERT_CALLSITE_HELPER generates the actual assert code. In Debug it does what you would
// expect of an assert and in release it tries to give hints to make the compiler generate better
// code.
#if defined(GPGMM_ENABLE_ASSERTS)
#    define GPGMM_ASSERT_CALLSITE_HELPER(file, func, line, condition)        \
        do {                                                                 \
            if (!(condition)) {                                              \
                gpgmm::HandleAssertionFailure(file, func, line, #condition); \
            }                                                                \
        } while (GPGMM_ASSERT_LOOP_CONDITION)
#else
#    if defined(GPGMM_COMPILER_MSVC)
// Avoid calling __assume(condition) directly because we can't assume the |condition| will always
// evaluate to be true at runtime and when false, the condition (or code) could be optimized out by
// MSVC and never executed. To protect the ASSERT's code, the equivelent generated code using
// __assume(0) is used.
#        define GPGMM_ASSERT_CALLSITE_HELPER(file, func, line, condition) \
            do {                                                          \
                if (!(condition)) {                                       \
                    GPGMM_UNREACHABLE();                                  \
                }                                                         \
            } while (GPGMM_ASSERT_LOOP_CONDITION)
#    elif defined(GPGMM_COMPILER_CLANG) && GPGMM_HAS_BUILTIN(__builtin_unreachable)
// Avoid using __builtin_assume since it results into clang assuming _every_ function call has a
// side effect. Alternatively, suppress these warnings with -Wno-assume or wrap _builtin_assume in
// pragmas. Since the generated code below is equivelent, replacing with __builtin_unreachable is
// used.
#        define GPGMM_ASSERT_CALLSITE_HELPER(file, func, line, condition) \
            do {                                                          \
                if (!(condition)) {                                       \
                    GPGMM_UNREACHABLE();                                  \
                }                                                         \
            } while (GPGMM_ASSERT_LOOP_CONDITION)
#    else
#        define GPGMM_ASSERT_CALLSITE_HELPER(file, func, line, condition) \
            do {                                                          \
                GPGMM_UNUSED(sizeof(condition));                          \
            } while (GPGMM_ASSERT_LOOP_CONDITION)
#    endif
#endif

#define GPGMM_ASSERT(condition) \
    GPGMM_ASSERT_CALLSITE_HELPER(__FILE__, __func__, __LINE__, condition)

#define GPGMM_ASSERT_UNREACHABLE()                                           \
    do {                                                                     \
        GPGMM_ASSERT(GPGMM_ASSERT_LOOP_CONDITION && "Unreachable code hit"); \
        GPGMM_UNREACHABLE();                                                 \
    } while (GPGMM_ASSERT_LOOP_CONDITION)

// Disable short-hand defined macros due to possible name clash.
// Instead, GPGMM will always use the already defined one.
#if !defined(ASSERT)
#    define ASSERT GPGMM_ASSERT
#endif

#if !defined(UNREACHABLE)
#    define UNREACHABLE GPGMM_ASSERT_UNREACHABLE
#endif

namespace gpgmm {

    void HandleAssertionFailure(const char* file,
                                const char* function,
                                int line,
                                const char* condition);

}

#endif  // GPGMM_UTILS_ASSERT_H_
