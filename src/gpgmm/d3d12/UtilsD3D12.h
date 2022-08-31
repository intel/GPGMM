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

#include "gpgmm/utils/Log.h"

#include <string>

namespace gpgmm::d3d12 {

    LogSeverity GetLogSeverity(D3D12_MESSAGE_SEVERITY messageSeverity);
    bool IsDepthFormat(DXGI_FORMAT format);
    bool IsAllowedToUseSmallAlignment(const D3D12_RESOURCE_DESC& Desc);
    HRESULT SetDebugObjectName(ID3D12Object* object, const std::string& name);
    DXGI_MEMORY_SEGMENT_GROUP GetMemorySegmentGroup(D3D12_MEMORY_POOL memoryPool, bool isUMA);

}  // namespace gpgmm::d3d12

#endif  // GPGMM_D3D12_UTILSD3D12_H_
