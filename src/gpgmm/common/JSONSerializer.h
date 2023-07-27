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

#ifndef SRC_GPGMM_COMMON_JSONSERIALIZER_H_
#define SRC_GPGMM_COMMON_JSONSERIALIZER_H_

#include "gpgmm/utils/JSONEncoder.h"

namespace gpgmm {

    // Forward declare common types.;
    struct MemoryAllocationRequest;
    struct MessageInfo;

    class JSONSerializer {
      public:
        static JSONDict Serialize();
        static JSONDict Serialize(const MessageInfo& info);
        static JSONDict Serialize(const MemoryAllocationRequest& desc);
        static JSONDict Serialize(const void* objectPtr);
    };

}  // namespace gpgmm

#endif  // SRC_GPGMM_COMMON_JSONSERIALIZER_H_
