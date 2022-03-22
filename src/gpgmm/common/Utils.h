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

#ifndef GPGMM_COMMON_UTILS_H_
#define GPGMM_COMMON_UTILS_H_

#include <string>

namespace gpgmm {

    template <typename T>
    void SafeDelete(T*& object) {
        delete object;
        object = nullptr;
    }

    template <typename T>
    void SafeDelete(T*&& object) {
        T*& lvalue = object;
        SafeDelete(lvalue);
    }

    // Converts pointer to hex address for output.
    std::string ToString(const void* object);

}  // namespace gpgmm

#endif  // GPGMM_COMMON_UTILS_H_
