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

#ifndef SRC_GPGMM_D3D12_BACKEND3D12_H_
#define SRC_GPGMM_D3D12_BACKEND3D12_H_

#include "gpgmm/common/Backend.h"

#include <gpgmm_d3d12.h>

namespace gpgmm::d3d12 {
    class ResidencyHeap;
    class ResourceAllocation;
    class ResourceAllocator;
    class ResidencyManager;
}  // namespace gpgmm::d3d12

// Compile-time mappings to/from API object/interface to down or up casts with only permitted API
// types. For example, `FromAPI(interface)` instead of `static_cast<Object*>(interface)`.
template <>
struct gpgmm::APIObjectTraits<gpgmm::d3d12::IResidencyHeap> {
    using DerivedType = gpgmm::d3d12::ResidencyHeap;
};

template <>
struct gpgmm::APIInterfaceTraits<gpgmm::d3d12::ResidencyHeap> {
    using InterfaceType = gpgmm::d3d12::IResidencyHeap;
};

template <>
struct gpgmm::APIObjectTraits<gpgmm::d3d12::IResourceAllocator> {
    using DerivedType = gpgmm::d3d12::ResourceAllocator;
};

template <>
struct gpgmm::APIInterfaceTraits<gpgmm::d3d12::ResourceAllocator> {
    using InterfaceType = gpgmm::d3d12::IResourceAllocator;
};

template <>
struct gpgmm::APIObjectTraits<gpgmm::d3d12::IResidencyManager> {
    using DerivedType = gpgmm::d3d12::ResidencyManager;
};

template <>
struct gpgmm::APIInterfaceTraits<gpgmm::d3d12::ResidencyManager> {
    using InterfaceType = gpgmm::d3d12::IResidencyManager;
};

namespace gpgmm::d3d12 {

    template <typename InterfaceType>
    auto FromAPI(InterfaceType&& basePtr) -> decltype(gpgmm::FromAPI(basePtr)) {
        return gpgmm::FromAPI(basePtr);
    }

    template <typename APIObjectType>
    auto ToAPI(APIObjectType&& objectPtr) -> decltype(gpgmm::ToAPI(objectPtr)) {
        return gpgmm::ToAPI(objectPtr);
    }

    struct BackendTraits {
        using AllocationType = ResourceAllocation;
        using AllocatorType = ResourceAllocator;
        using MemoryType = ResidencyHeap;
    };

    template <typename T>
    auto ToBackend(T&& common) -> decltype(gpgmm::ToBackend<BackendTraits>(common)) {
        return gpgmm::ToBackend<BackendTraits>(common);
    }

}  // namespace gpgmm::d3d12

#endif
