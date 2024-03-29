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

// export.h : Defines GPGMM_EXPORT, a macro for exporting functions from the DLL

#ifndef GPGMM_EXPORT_H_
#define GPGMM_EXPORT_H_

#if defined(GPGMM_SHARED_LIBRARY)
#    if defined(_WIN32)
#        if defined(GPGMM_IMPLEMENTATION)
#            define GPGMM_EXPORT __declspec(dllexport)
#        else
#            define GPGMM_EXPORT __declspec(dllimport)
#        endif
#    else  // defined(_WIN32)
#        if defined(GPGMM_IMPLEMENTATION)
#            define GPGMM_EXPORT __attribute__((visibility("default")))
#        else
#            define GPGMM_EXPORT
#        endif
#    endif  // defined(_WIN32)
#else       // defined(GPGMM_SHARED_LIBRARY)
#    define GPGMM_EXPORT
#endif  // defined(GPGMM_SHARED_LIBRARY)

#endif  // GPGMM_EXPORT_H_
