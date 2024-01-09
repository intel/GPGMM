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

#ifndef SRC_GPGMM_COMMON_BACKEND_H_
#define SRC_GPGMM_COMMON_BACKEND_H_

namespace gpgmm {

    // Forward declare common types.
    class MemoryAllocationBase;
    class MemoryAllocatorBase;
    class MemoryBase;

    template <typename CommonType, typename BackendTraits>
    struct CommonTraits;

    // Define common types.
    template <typename BackendTraits>
    struct CommonTraits<MemoryAllocationBase, BackendTraits> {
        using CommonType = typename BackendTraits::AllocationType;
    };

    template <typename BackendTraits>
    struct CommonTraits<MemoryAllocatorBase, BackendTraits> {
        using CommonType = typename BackendTraits::AllocatorType;
    };

    template <typename BackendTraits>
    struct CommonTraits<MemoryBase, BackendTraits> {
        using CommonType = typename BackendTraits::MemoryType;
    };

    // Convert common to backend type.

    template <typename BackendTraits, typename CommonT>
    typename CommonTraits<CommonT, BackendTraits>::CommonType* ToBackend(CommonT* common) {
        return static_cast<typename CommonTraits<CommonT, BackendTraits>::CommonType*>(common);
    }

    template <typename BackendTraits, typename CommonT>
    const typename CommonTraits<CommonT, BackendTraits>::CommonType* ToBackend(
        const CommonT* common) {
        return static_cast<const typename CommonTraits<CommonT, BackendTraits>::CommonType*>(
            common);
    }

}  // namespace gpgmm

#endif  // SRC_GPGMM_COMMON_BACKEND_H_
