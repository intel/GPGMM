// Copyright 2017 The Dawn Authors
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

#ifndef SRC_GPGMM_D3D12_D3D12PLATFORM_H_
#define SRC_GPGMM_D3D12_D3D12PLATFORM_H_

#include <d3d12.h>
#include <wrl.h>

// Keep backwards compatibility when using D3D12 feature flags that are only defined in a newer
// D3D12.h versions.
// Only once ALL builds upgrade to the newer D3D12.h version, can these defines be safely
// removed.
#define D3D12_HEAP_FLAG_CREATE_NOT_RESIDENT static_cast<D3D12_HEAP_FLAGS>(0x800)

using Microsoft::WRL::ComPtr;

// D3D12 doesn't provide a allocation info definition for non-resource heap types (eg.
// descriptor heaps) but the info is the otherwise the same as resource heaps.
using HEAP_ALLOCATION_INFO = D3D12_RESOURCE_ALLOCATION_INFO;

#endif  // SRC_GPGMM_D3D12_D3D12PLATFORM_H_
