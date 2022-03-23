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

#ifndef GPGMM_BACKEND_H_
#define GPGMM_BACKEND_H_

namespace gpgmm {

    // Forward declare common types.
    class MemoryBase;
    class MemoryAllocation;

    template <typename CommonType, typename BackendTrait>
    struct CommonTrait;

    // Define common types.

    template <typename BackendTrait>
    struct CommonTrait<MemoryBase, BackendTrait> {
        using CommonType = typename BackendTrait::MemoryType;
    };

    template <typename BackendTrait>
    struct CommonTrait<MemoryAllocation, BackendTrait> {
        using CommonType = typename BackendTrait::AllocationType;
    };

    // Convert common to backend type.

    template <typename BackendTrait, typename CommonT>
    typename CommonTrait<CommonT, BackendTrait>::CommonType* ToBackend(CommonT* common) {
        return reinterpret_cast<typename CommonTrait<CommonT, BackendTrait>::CommonType*>(common);
    }

    template <typename BackendTrait, typename CommonT>
    const typename CommonTrait<CommonT, BackendTrait>::CommonType* ToBackend(
        const CommonT* common) {
        return reinterpret_cast<const typename CommonTrait<CommonT, BackendTrait>::CommonType*>(
            common);
    }

}  // namespace gpgmm

#endif  // GPGMM_TOBACKEND_H_
