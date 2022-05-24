[![win_clang_rel_x64](https://github.com/intel/GPGMM/actions/workflows/win_clang_rel_x64.yaml/badge.svg)](https://github.com/intel/GPGMM/actions/workflows/win_clang_rel_x64.yaml)
[![win_clang_dbg_x64](https://github.com/intel/GPGMM/actions/workflows/win_clang_dbg_x64.yaml/badge.svg)](https://github.com/intel/GPGMM/actions/workflows/win_clang_dbg_x64.yaml)
[![win_msvc_dbg_x64](https://github.com/intel/GPGMM/actions/workflows/win_msvc_dbg_x64.yaml/badge.svg)](https://github.com/intel/GPGMM/actions/workflows/win_msvc_dbg_x64.yaml)
[![win_msvc_rel_x64](https://github.com/intel/GPGMM/actions/workflows/win_msvc_rel_x64.yaml/badge.svg)](https://github.com/intel/GPGMM/actions/workflows/win_msvc_rel_x64.yaml)

[![Average time to resolve an issue](http://isitmaintained.com/badge/resolution/intel/gpgmm.svg)](http://isitmaintained.com/project/intel/gpgmm "Average time to resolve an issue") [![Percentage of issues still open](http://isitmaintained.com/badge/open/intel/gpgmm.svg)](http://isitmaintained.com/project/intel/gpgmm "Percentage of issues still open")

# GPGMM

GPGMM is a General-Purpose GPU Memory Management C++ library used by GPU applications or middleware libraries that rely on low-level graphics and compute APIs (D3D12 or Vulkan) for "explicit" memory management. GPGMM is a fast, multi-threaded Video Memory Manager (VidMM) implementation that replaces what older "implicit" graphics and compute APIs (D3D11 or OpenGL) had accomplished through the GPU driver.

* [API Documentation](https://intel.github.io/GPGMM/)
* [Changelog](https://github.com/intel/GPGMM/releases)
* [License](https://github.com/intel/GPGMM/blob/main/LICENSE)

## Build and Run

### Install `depot_tools`

GPGMM uses the Chromium build system and dependency management so you need to [install depot_tools] and add it to the PATH.

[install depot_tools]: http://commondatastorage.googleapis.com/chrome-infra-docs/flat/depot_tools/docs/html/depot_tools_tutorial.html#_setting_up

**Notes**:
 * On Windows, you'll need to set the environment variable `DEPOT_TOOLS_WIN_TOOLCHAIN=0`. This tells depot_tools to use your locally installed version of Visual Studio (by default, depot_tools will try to download a Google-internal version).

### Get the code

Get the source code as follows:

```sh
# Clone the repo as "GPGMM"
> git clone https://github.com/intel/GPGMM.git GPGMM && cd GPGMM

# Bootstrap the gclient configuration
> cp scripts/standalone.gclient .gclient

# Fetch external dependencies and toolchains with gclient
> gclient sync
```

### Setting up the build
Generate build files using `gn args out/Debug` or `gn args out/Release`.

A text editor will appear asking build arguments, the most common argument is `is_debug=true/false`; otherwise `gn args out/Release --list` shows all the possible options.

To build with a backend, please set the corresponding argument from following table.

| Backend | Build argument |
|---------|--------------|
| DirectX 12 | `gpgmm_enable_d3d12=true` |
| Vulkan | `gpgmm_enable_vk=true` |

### Build

Then use `ninja -C out/Release` or `ninja -C out/Debug` to build.

### Run tests

```sh
> cd out/Debug
```

#### Run unit tests:
```sh
> gpgmm_unittests
```

Unit tests check the front-end code in isolation or without a GPU.

#### Run end2end tests:
```sh
> gpgmm_end2end_tests
```

End2End tests check both the front AND backend code with a GPU.

#### Run capture replay tests:
```sh
> gpgmm_capture_replay_tests
```

Capture replay checks using pre-recorded memory patterns with a GPU.

#### Run fuzzing tests:
```sh
> gpgmm_*_fuzzer
```

Fuzzer checks using random memory patterns with a GPU.

## How do I use it?

First create an allocator then second, create allocations from it:

### D3D12
```cpp
// Required
gpgmm::d3d12::ALLOCATOR_DESC allocatorDesc = {};
allocatorDesc.Device = Device;
allocatorDesc.Adapter = Adapter;

// Use CheckFeatureSupport
allocatorDesc.IsUMA = true;
allocatorDesc.ResourceHeapTier = D3D12_RESOURCE_HEAP_TIER_1;

ComPtr<gpgmm::d3d12::ResidencyManager> residency; // Optional
ComPtr<gpgmm::d3d12::ResourceAllocator> allocator;
gpgmm::d3d12::ResourceAllocator::CreateAllocator(desc, &allocator, &residency);
```

```cpp
D3D12_RESOURCE_DESC& resourceDesc = {};
D3D12_RESOURCE_STATES initialState = {}
gpgmm::d3d12::ALLOCATION_DESC allocationDesc = {};

ComPtr<gpgmm::d3d12::ResourceAllocation> allocation;
allocator->CreateResource(allocationDesc, resourceDesc, initialState, nullptr, &allocation);
```

GPUs do not support page-faulting, so it's up the GPU application to avoid using too much
physical GPU memory. GPGMM integrates residency into the resource allocators to simplify and optimize allocation:

```cpp
gpgmm::d3d12::ResidencySet set;
set.Insert(allocation->GetMemory());

residency->ExecuteCommandList(&queue, &commandList, &set, 1);

// Prepare for next frame.
set.Reset();
```

Residency also works for non-resources too:

```cpp
// Wraps a ID3D12DescriptorHeap, ID3D12QueryHeap, etc.
class HeapWrapper : public gpgmm::d3d12::Heap {};

HeapWrapper heap;
residency->InsertHeap(&heap);
residency->LockHeap(heap) // Pin it (eg. shader-visible)
```

To clean-up, simply call `Release()` once the is GPU is finished.

### Vulkan

```cpp
gpgmm::vk::GpCreateAllocatorInfo allocatorInfo = {};

gpgmm::vk::GpResourceAllocator resourceAllocator;
gpgmm::vk::gpCreateResourceAllocator(allocatorInfo, &resourceAllocator)
```

```cpp
VkBufferCreateInfo bufferInfo = {};
VkBuffer buffer;

gpgmm::vk::GpResourceAllocation allocation;
gpgmm::vk::GpResourceAllocationCreateInfo allocationInfo = {};

gpgmm::vk::gpCreateBuffer(resourceAllocator, &bufferInfo, &buffer, &allocationInfo, &allocation)
```

Then to clean-up:
```cpp
gpgmm::vk::gpDestroyBuffer(resourceAllocator, buffer, allocation); // Make sure GPU is finished!
gpgmm::vk::gpDestroyResourceAllocator(resourceAllocator);
```

## Project/build integration
GPGMM has built-in GN or CMake build targets.

### GN

BUILD.gn
```gn
source_set("proj") {
  deps = [ "${gpgmm_dir}:gpgmm" ]
}
```
Create `build_overrides/gpgmm.gni` file in root directory.

### CMake

CMakeLists.txt
```cmake
add_subdirectory(gpgmm)
target_include_directories(proj PRIVATE gpgmm/src/include gpgmm/src)
target_link_libraries(proj PRIVATE gpgmm ...)
```

### Visual Studio (MSVC)

Dynamic Linked Library (DLL)

Use `is_clang=false gpgmm_shared_library=true` when [Setting up the build](#Setting-up-the-build).
Then use `ninja -C out/Release gpgmm` or `ninja -C out/Debug gpgmm` to build the shared library (DLL).

Copy the DLL into the `$(OutputPath)` folder and configure the VS build:
1. Highlight project in the **Solution Explorer**, and then select **Project > Properties**.
2. Under **Configuration Properties > C/C++ > General**, add `gpgmm\src` and `gpgmm\src\include` to **Additional Include Directories**.
3. Under **Configuration Properties > Linker > Input**, add ``gpgmm.dll.lib`` to **Additional Dependencies**.
4. Under **Configuration Properties > Linker > General**, add the folder path to `out\Release` to **Additional Library Directories**.

Then include the public header:
```cpp
#include <gpgmm_*.h> // Ex. gpgmm_d3d12.h
```

# Prerequisites
* Error handing uses API error codes (`HRESULT` and `VkResult` for D3D12 and Vulkan, respectively).

## License

Apache 2.0 Public License, please see [LICENSE](/LICENSE).
