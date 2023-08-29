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

#ifndef SRC_GPGMM_COMMON_GPUINFO_H_
#define SRC_GPGMM_COMMON_GPUINFO_H_

#include <cstdint>

namespace gpgmm {

    enum class GPUVendor {
        kAMD_Vendor = 4098,
        kARM_Vendor = 5045,
        kImagination_Vendor = 4112,
        kIntel_Vendor = 32902,
        kNvidia_Vendor = 4318,
        kQualcomm_Vendor = 20803,
        kMicrosoft_Vendor = 0x1414,
    };

    enum class GPUDevice {
        kWARP_Device = 0x8c,
    };

}  // namespace gpgmm

#endif  // SRC_GPGMM_COMMON_GPUINFO_H_
