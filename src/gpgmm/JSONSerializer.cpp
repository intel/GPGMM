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

#include "gpgmm/JSONSerializer.h"

#include "gpgmm/Allocator.h"
#include "gpgmm/MemoryAllocator.h"
#include "gpgmm/MemoryPool.h"

#include <sstream>

namespace gpgmm {

    // Messages with equal or greater to severity will be logged.
    LogSeverity gRecordEventLevel = LogSeverity::Info;

    void SetRecordEventLevel(const LogSeverity& level) {
        gRecordEventLevel = level;
    }

    const LogSeverity& GetRecordEventLevel() {
        return gRecordEventLevel;
    }

    // static
    std::string JSONSerializer::AppendTo(const POOL_DESC& desc) {
        std::stringstream ss;
        ss << "{ "
           << "\"PoolSize\": " << desc.PoolSize << " }";
        return ss.str();
    }

    // static
    std::string JSONSerializer::AppendTo(const ALLOCATOR_MESSAGE& desc) {
        std::stringstream ss;
        ss << "{ "
           << "\"Description\": \"" << desc.Description << "\", "
           << "\"ID\": " << desc.ID << " }";
        return ss.str();
    }

    // static
    std::string JSONSerializer::AppendTo(const MEMORY_ALLOCATOR_INFO& info) {
        std::stringstream ss;
        ss << "{ "
           << "\"UsedBlockCount\": " << info.UsedBlockCount << ", "
           << "\"UsedMemoryCount\": " << info.UsedMemoryCount << ", "
           << "\"UsedBlockUsage\": " << info.UsedBlockUsage << ", "
           << "\"FreeMemoryUsage\": " << info.FreeMemoryUsage << ", "
           << "\"UsedMemoryUsage\": " << info.UsedMemoryUsage << " }";
        return ss.str();
    }

}  // namespace gpgmm
