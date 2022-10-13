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

#ifndef FUZZER_D3D12FUZZER_H_
#define FUZZER_D3D12FUZZER_H_

#include <gpgmm_d3d12.h>

#include <wrl.h>  // for Microsoft::WRL::ComPtr

using Microsoft::WRL::ComPtr;

uint64_t UInt8ToUInt64(const uint8_t* src);

HRESULT CreateResourceAllocatorDesc(gpgmm::d3d12::ALLOCATOR_DESC* allocatorDesc);

D3D12_RESOURCE_DESC CreateBufferDesc(uint64_t width, uint64_t alignment = 0);

#endif  // FUZZER_D3D12FUZZER_H_
