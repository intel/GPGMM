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

#ifndef GPGMM_COMMON_JSONSERIALIZER_H_
#define GPGMM_COMMON_JSONSERIALIZER_H_

#include "gpgmm/utils/JSONEncoder.h"

namespace gpgmm {

    // Forward declare common types.
    struct MemoryPoolInfo;
    struct MemoryAllocatorStats;
    struct MemoryAllocationInfo;
    struct MemoryAllocationRequest;
    struct EventMessageInfo;

    class JSONSerializer {
      public:
        static JSONDict Serialize();
        static JSONDict Serialize(const EventMessageInfo& info);
        static JSONDict Serialize(const MemoryAllocatorStats& info);
        static JSONDict Serialize(const MemoryAllocationRequest& desc);
        static JSONDict Serialize(const MemoryAllocationInfo& info);
        static JSONDict Serialize(const MemoryPoolInfo& desc);
        static JSONDict Serialize(const void* objectPtr);
    };

}  // namespace gpgmm

#endif  // GPGMM_COMMON_JSONSERIALIZER_H_
