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

#ifndef SRC_GPGMM_COMMON_SIZECLASS_H_
#define SRC_GPGMM_COMMON_SIZECLASS_H_

#include <array>
#include <string>

// Convert sizes, in bytes, to/from SI prefix.
#define GPGMM_KB_TO_BYTES(bytes) ((bytes)*1024ull)
#define GPGMM_MB_TO_BYTES(bytes) (GPGMM_KB_TO_BYTES(bytes) * 1024ull)
#define GPGMM_GB_TO_BYTES(bytes) (GPGMM_MB_TO_BYTES(bytes) * 1024ull)

#define GPGMM_BYTES_TO_KB(bytes) ((bytes) / 1024ull)
#define GPGMM_BYTES_TO_MB(bytes) (GPGMM_BYTES_TO_KB(bytes) / 1024ull)
#define GPGMM_BYTES_TO_GB(bytes) (GPGMM_BYTES_TO_MB(bytes) / 1024ull)

namespace gpgmm {

    struct SizeClassInfo {
        uint64_t SizeInBytes;
        uint64_t Alignment;
    };

    // Returns the printable string of |bytes| in storage units (eg. 2*1024 =>
    // 2 MB).
    std::string GetBytesToSizeInUnits(uint64_t bytes);

    // Generates array containing values in range [2^N1...2^N2], where N2 > N1.
    template <size_t N1, size_t N2>
    static constexpr std::array<SizeClassInfo, N2 - N1 + 1> GeneratePowerOfTwoSizes() {
        static_assert(N2 > N1, "Invalid range specified.");
        std::array<SizeClassInfo, N2 - N1 + 1> sizeArray{};
        for (size_t i = N1; i < N2; ++i) {
            sizeArray[i] = {static_cast<uint64_t>(1ull << i), i};
        }
        return sizeArray;
    }

    template <size_t N, size_t alignment>
    static constexpr std::array<SizeClassInfo, N> GenerateAlignedSizes() {
        std::array<SizeClassInfo, N> sizeArray{};
        for (size_t i = 1; i < N; ++i) {
            sizeArray[i] = {i * alignment, alignment};
        }
        return sizeArray;
    }

    class MemorySizeClass {
      protected:
        static constexpr auto GenerateAllClassSizes() {
            return kPowerOfTwoCacheSizes;
        }

      private:
        static constexpr auto kPowerOfTwoCacheSizes = GeneratePowerOfTwoSizes<1, 27>();
    };

}  // namespace gpgmm

#endif  // SRC_GPGMM_COMMON_SIZECLASS_H_
