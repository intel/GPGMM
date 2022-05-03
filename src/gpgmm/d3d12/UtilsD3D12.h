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
#ifndef GPGMM_D3D12_UTILSD3D12_H_
#define GPGMM_D3D12_UTILSD3D12_H_

#include "gpgmm/d3d12/d3d12_platform.h"
#include "gpgmm/utils/NonCopyable.h"

#include <memory>

namespace gpgmm { namespace d3d12 {

    DXGI_MEMORY_SEGMENT_GROUP GetPreferredMemorySegmentGroup(ID3D12Device* device,
                                                             bool isUMA,
                                                             D3D12_HEAP_TYPE heapType);
    bool IsDepthFormat(DXGI_FORMAT format);
    bool IsAllowedToUseSmallAlignment(const D3D12_RESOURCE_DESC& Desc);

    struct UniqueComPtrDeleter {
        template <typename T>
        void operator()(T* UniqueComPtr) const {
            UniqueComPtr->Release();
        }
    };

    // Manages a ComPtr like std::unique_ptr.
    template <typename T, class Deleter = UniqueComPtrDeleter>
    struct UniqueComPtr : public std::unique_ptr<T, Deleter>, public NonCopyable {
        static_assert(std::is_empty<Deleter>::value,
                      "UniqueComPtr doesn't support stateful deleter.");

        typedef std::unique_ptr<T, Deleter> UniquePtrT;
        using UnderlyingUniquePtrT = typename UniquePtrT::pointer;

        UniqueComPtr() : UniquePtrT(nullptr) {
        }

        explicit UniqueComPtr(T* ptr) : UniquePtrT(ptr) {
            if (ptr != nullptr) {
                ptr->AddRef();
            }
        }

        template <typename OtherDeleter>
        UniqueComPtr(UniqueComPtr<T, OtherDeleter>&& other) : UniquePtrT(other.release()) {
        }

        template <typename OtherDeleter>
        UniqueComPtr& operator=(UniqueComPtr<T, OtherDeleter>&& other) {
            UniquePtrT::reset(other.release());
            return *this;
        }

        UniqueComPtr& operator=(UnderlyingUniquePtrT ptr) {
            reset(ptr);
            return *this;
        }

        UniqueComPtr& operator=(std::nullptr_t ptr) {
            reset(ptr);
            return *this;
        }

        void reset(UnderlyingUniquePtrT ptr = UnderlyingUniquePtrT()) {
            if (ptr != nullptr) {
                ptr->AddRef();
            }
            UniquePtrT::reset(ptr);
        }

        void reset(std::nullptr_t ptr) {
            UniquePtrT::reset(ptr);
        }

        T** operator&() {
            ASSERT(*this == nullptr);
            return reinterpret_cast<T**>(this);
        }

        T* const* operator&() const {
            return reinterpret_cast<T* const*>(this);
        }

        using UniquePtrT::get;
        using UniquePtrT::release;
        using UniquePtrT::operator->;
        using UniquePtrT::operator*;
        using UniquePtrT::operator bool;
    };

}}  // namespace gpgmm::d3d12

#endif  // GPGMM_D3D12_UTILSD3D12_H_
