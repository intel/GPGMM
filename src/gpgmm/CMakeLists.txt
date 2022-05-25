# Copyright 2020 The Dawn Authors
# Copyright 2021 The GPGMM Authors
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

add_library(gpgmm)

target_link_libraries(gpgmm
    PRIVATE gpgmm_utils
            gpgmm_common
            gpgmm_common_config
)

# Only win32 app needs to link with user32.lib
# In UWP, all availiable APIs are defined in WindowsApp.lib
# and is automatically linked when WINDOWS_STORE set
if (WIN32 AND NOT WINDOWS_STORE)
    target_link_libraries(gpgmm PRIVATE user32.lib)
endif()

# DXGIGetDebugInterface1 is defined in dxgi.lib
# But this API is tagged as a development-only capability
# which implies that linking to this function will cause
# the application to fail Windows store certification
# So we only link to it in debug build when compiling for UWP.
# In win32 we load dxgi.dll using LoadLibrary
# so no need for static linking.
if (WINDOWS_STORE)
    target_link_libraries(gpgmm PRIVATE debug dxgi.lib)
endif()

if (GPGMM_ENABLE_D3D12)
    target_sources(gpgmm PRIVATE
        "d3d12/BufferAllocatorD3D12.cpp"
        "d3d12/BufferAllocatorD3D12.h"
        "d3d12/DebugResourceAllocatorD3D12.cpp"
        "d3d12/DebugResourceAllocatorD3D12.h"
        "d3d12/CapsD3D12.cpp"
        "d3d12/CapsD3D12.h"
        "d3d12/ErrorD3D12.cpp"
        "d3d12/ErrorD3D12.h"
        "d3d12/FenceD3D12.cpp"
        "d3d12/FenceD3D12.h"
        "d3d12/HeapD3D12.cpp"
        "d3d12/HeapD3D12.h"
        "d3d12/IUnknownImplD3D12.cpp"
        "d3d12/IUnknownImplD3D12.h"
        "d3d12/JSONSerializerD3D12.cpp"
        "d3d12/JSONSerializerD3D12.h"
        "d3d12/ResidencyManagerD3D12.cpp"
        "d3d12/ResidencyManagerD3D12.h"
        "d3d12/ResidencySetD3D12.cpp"
        "d3d12/ResidencySetD3D12.h"
        "d3d12/ResourceAllocationD3D12.cpp"
        "d3d12/ResourceAllocationD3D12.h"
        "d3d12/ResourceAllocatorD3D12.cpp"
        "d3d12/ResourceAllocatorD3D12.h"
        "d3d12/ResourceHeapAllocatorD3D12.cpp"
        "d3d12/ResourceHeapAllocatorD3D12.h"
        "d3d12/UtilsD3D12.cpp"
        "d3d12/UtilsD3D12.h"
        "d3d12/d3d12_platform.h"
    )
    target_link_libraries(gpgmm PRIVATE dxguid.lib)
endif()

if (GPGMM_ENABLE_VK)
  target_sources(gpgmm PRIVATE
        "vk/CapsVk.cpp"
        "vk/CapsVk.h"
        "vk/DeviceMemoryAllocatorVk.cpp"
        "vk/DeviceMemoryAllocatorVk.h"
        "vk/DeviceMemoryVk.cpp"
        "vk/DeviceMemoryVk.h"
        "vk/ErrorVk.h"
        "vk/ResourceAllocatorVk.cpp"
        "vk/ResourceAllocatorVk.h"
        "vk/FunctionsVk.cpp"
        "vk/FunctionsVk.h"
        "vk/vk_platform.h"
    )

    target_link_libraries(gpgmm PUBLIC Vulkan-Headers)
    target_include_directories(gpgmm PRIVATE ${GPGMM_VK_TOOLS_DIR})

endif()

################################################################################
# Build subdirectories
################################################################################
add_subdirectory(utils)
add_subdirectory(common)