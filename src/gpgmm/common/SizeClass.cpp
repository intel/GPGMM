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

#include "gpgmm/common/SizeClass.h"

#include "gpgmm/utils/Assert.h"
#include "gpgmm/utils/Limits.h"

#include <iomanip>
#include <sstream>

namespace gpgmm {

    std::string GetBytesToSizeInUnits(uint64_t bytes) {
        // UINT_MAX is given special "invalid" size.
        if (bytes == kInvalidSize) {
            return "INVALID_SIZE";
        }

        const char* unitsArray[] = {"B", "KB", "MB", "GB", "TB", "PB", "EB", "ZB", "YB"};
        size_t unitIndex = 0;
        while (bytes >= 1024 && unitIndex < sizeof(unitsArray) / sizeof(unitsArray[0]) - 1) {
            bytes /= 1024;
            unitIndex++;
        }
        std::ostringstream oss;
        oss << std::fixed << std::setprecision(2) << bytes << " " << unitsArray[unitIndex];
        return oss.str();
    }

}  // namespace gpgmm
