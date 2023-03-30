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

#ifndef GPGMM_UTILS_UTILS_H_
#define GPGMM_UTILS_UTILS_H_

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
    std::string ToString(T object) noexcept {
        std::stringstream output;
        output << object;
        return output.str();
    }

    // Converts T to a hexadecimal string.
    template <typename T>
    std::string ToHexStr(T object) noexcept {
        std::stringstream stream;
        stream << "0x" << std::hex << object;
        return stream.str();
    }

    // Used to combine multiple ToString calls for concatenation.
    // Eg. ToString("a", "b", "c") == "abc".
    template <typename T, typename... Args>
    std::string ToString(T object, Args... args) {
        return ToString(object) + ToString(args...);
    }

    template <typename T, std::size_t N1, std::size_t N2>
    constexpr auto ConstexprConcat(std::array<T, N1> lhs, std::array<T, N2> rhs) {
        std::array<T, N1 + N2> sizeArray{};
        size_t i = 0;

        for (auto& item : lhs) {
            sizeArray[i] = std::move(item);
            ++i;
        }

        for (auto& item : rhs) {
            sizeArray[i] = std::move(item);
            ++i;
        }

        return sizeArray;
    }

}  // namespace gpgmm

#endif  // GPGMM_UTILS_UTILS_H_
