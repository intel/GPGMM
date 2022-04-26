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

#include <sstream>
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

    template <typename T>
    void SafeRelease(T& allocation) {
        if (allocation != nullptr) {
            SafeDelete(allocation->GetMemory());
            allocation = nullptr;
        }
    }

    // Converts pointer to hex address for output.
    std::string ToString(const void* object);

    template <typename T>
    std::string ToString(T object) {
        std::stringstream output;
        output << object;
        return output.str();
    }

    // Used to combine multiple ToString calls for concatenation.
    // Eg. ToString("a", "b", "c") == "abc".
    template <typename T, typename... Args>
    std::string ToString(T object, Args... args) {
        return ToString(object) + ToString(args...);
    }

}  // namespace gpgmm

#endif  // GPGMM_COMMON_UTILS_H_
