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

#ifndef GPGMM_ALLOCATOR_H_
#define GPGMM_ALLOCATOR_H_

#include "gpgmm/utils/NonCopyable.h"

#include <string>

namespace gpgmm {

    enum ALLOCATOR_MESSAGE_ID {
        ALLOCATOR_MESSAGE_ID_UNKNOWN,
        ALLOCATOR_MESSAGE_ID_SIZE_EXCEEDED,
        ALLOCATOR_MESSAGE_ID_ALIGNMENT_MISMATCH,
        ALLOCATOR_MESSAGE_ID_ALLOCATOR_FAILED,
    };

    class AllocatorBase : public NonCopyable {
      public:
        AllocatorBase() = default;
        virtual ~AllocatorBase() = default;
        virtual const char* GetTypename() const {
            return "Allocator";
        }
    };

}  // namespace gpgmm

#endif  // GPGMM_ALLOCATOR_H_
