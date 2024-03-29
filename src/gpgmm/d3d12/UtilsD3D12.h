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
#ifndef SRC_GPGMM_D3D12_UTILSD3D12_H_
#define SRC_GPGMM_D3D12_UTILSD3D12_H_

#include "gpgmm/common/Message.h"
#include "gpgmm/d3d12/D3D12Platform.h"

#include <gpgmm_d3d12.h>

namespace gpgmm::d3d12 {

    MessageSeverity GetMessageSeverity(D3D12_MESSAGE_SEVERITY messageSeverity);
    bool IsDepthFormat(DXGI_FORMAT format);
    bool IsAllowedToUseSmallAlignment(const D3D12_RESOURCE_DESC& Desc);
    HRESULT SetDebugObjectName(ID3D12Object* object, LPCWSTR name);
    RESIDENCY_HEAP_SEGMENT GetMemorySegment(D3D12_MEMORY_POOL memoryPool, bool isUMA);
    const char* GetMemorySegmentName(RESIDENCY_HEAP_SEGMENT heapSegment, bool isUMA);
    ComPtr<ID3D12Device> GetDevice(ID3D12DeviceChild* pDeviceChild);
    bool IsTexture(const D3D12_RESOURCE_DESC& resourceDescriptor);
    bool IsBuffer(const D3D12_RESOURCE_DESC& resourceDescriptor);

}  // namespace gpgmm::d3d12

#endif  // SRC_GPGMM_D3D12_UTILSD3D12_H_
