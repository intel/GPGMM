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

#ifndef GPGMM_COMMON_MEMORYSIZE_H_
#define GPGMM_COMMON_MEMORYSIZE_H_

namespace gpgmm {

    struct MEMORY_SIZE_INFO {
        uint64_t SizeInBytes;
    };

    class MemorySize {
      public:
        static const size_t kPowerOfTwoClassSize;
        static const MEMORY_SIZE_INFO kPowerOfTwoCacheSizes[];
    };

    // clang-format off
    const size_t MemorySize::kPowerOfTwoClassSize = 27;
    const MEMORY_SIZE_INFO MemorySize::kPowerOfTwoCacheSizes[MemorySize::kPowerOfTwoClassSize] = {
      {1},
      {2},
      {4},
      {8},
      {16},
      {32},
      {64},
      {128},
      {256},
      {512},
      {1024},
      {2048},
      {4096},
      {8192},
      {16384},
      {32768},
      {65536},
      {131072},
      {262144},
      {524288},
      {1048576},
      {2097152},
      {4194304},
      {8388608},
      {16777216},
      {33554432},
      {67108864},
    };
    // clang-format on

}  // namespace gpgmm

#endif  // GPGMM_COMMON_MEMORYSIZE_H_
