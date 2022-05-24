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

#ifndef GPGMM_COMMON_JSONSERIALIZER_H_
#define GPGMM_COMMON_JSONSERIALIZER_H_

#include "gpgmm/utils/JSONEncoder.h"

namespace gpgmm {

    // Forward declare common types.
    struct MEMORY_POOL_INFO;
    struct MEMORY_ALLOCATOR_INFO;
    struct MEMORY_ALLOCATION_INFO;
    struct MEMORY_ALLOCATION_REQUEST;
    struct LOG_MESSAGE;

    class JSONSerializer {
      public:
        static JSONDict Serialize();
        static JSONDict Serialize(const LOG_MESSAGE& desc);
        static JSONDict Serialize(const MEMORY_ALLOCATOR_INFO& info);
        static JSONDict Serialize(const MEMORY_ALLOCATION_REQUEST& desc);
        static JSONDict Serialize(const MEMORY_ALLOCATION_INFO& info);
        static JSONDict Serialize(const MEMORY_POOL_INFO& desc);
        static JSONDict Serialize(const void* objectPtr);
    };

}  // namespace gpgmm

#endif  // GPGMM_COMMON_JSONSERIALIZER_H_
