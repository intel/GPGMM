| Build Config | Build Status |
---------------|--------------|
| GN/Clang     | [![win_x64_gn_clang_rel](https://github.com/intel/GPGMM/actions/workflows/win_x64_gn_clang_rel.yaml/badge.svg)](https://github.com/intel/GPGMM/actions/workflows/win_x64_gn_clang_rel.yaml)[![win_x64_gn_clang_dbg](https://github.com/intel/GPGMM/actions/workflows/win_x64_gn_clang_dbg.yaml/badge.svg)](https://github.com/intel/GPGMM/actions/workflows/win_x64_gn_clang_dbg.yaml)[![win_x64_gn_msvc_dbg](https://github.com/intel/GPGMM/actions/workflows/win_x64_gn_msvc_dbg.yaml/badge.svg)](https://github.com/intel/GPGMM/actions/workflows/win_x64_gn_msvc_dbg.yaml)[![win_x64_gn_msvc_rel](https://github.com/intel/GPGMM/actions/workflows/win_x64_gn_msvc_rel.yaml/badge.svg)](https://github.com/intel/GPGMM/actions/workflows/win_x64_gn_msvc_rel.yaml) |
| CMake/MSVC   | [![win_x64_cmake_msvc_dbg](https://github.com/intel/GPGMM/actions/workflows/win_x64_cmake_msvc_dbg.yaml/badge.svg)](https://github.com/intel/GPGMM/actions/workflows/win_x64_cmake_msvc_dbg.yaml)[![win_x64_cmake_msvc_rel](https://github.com/intel/GPGMM/actions/workflows/win_x64_cmake_msvc_rel.yaml/badge.svg)](https://github.com/intel/GPGMM/actions/workflows/win_x64_cmake_msvc_rel.yaml)  |

[![Average time to resolve an issue](http://isitmaintained.com/badge/resolution/intel/gpgmm.svg)](http://isitmaintained.com/project/intel/gpgmm "Average time to resolve an issue") [![Percentage of issues still open](http://isitmaintained.com/badge/open/intel/gpgmm.svg)](http://isitmaintained.com/project/intel/gpgmm "Percentage of issues still open")

# GPGMM

GPGMM is a General-Purpose GPU Memory Management C++ library used by GPU applications/runtimes that use modern graphics and compute APIs (D3D12 or Vulkan) that allow low-level memory management. GPGMM is a fast, multi-threaded, full-fledged GPU Memory Manager (GMM) implementation that replaces what older graphics and compute APIs (D3D11 or OpenGL) had accomplished through the GPU driver.

* [API Documentation](https://intel.github.io/GPGMM/)
* [Changelog](https://github.com/intel/GPGMM/releases)
* [License](https://github.com/intel/GPGMM/blob/main/LICENSE)
* [Design Doc](https://github.com/intel/GPGMM/blob/main/docs/DESIGN.md)

## How do I use it?

### Prerequisites
* Error handing uses GPU API error codes (`HRESULT` and `VkResult` for D3D12 and Vulkan, respectively).

First create an allocator then create allocations from it:

### D3D12
```cpp
#include <gpgmm_d3d12.h>

gpgmm::d3d12::RESOURCE_ALLOCATOR_DESC allocatorDesc = {};

ComPtr<gpgmm::d3d12::IResidencyManager> residency; // Optional
ComPtr<gpgmm::d3d12::IResourceAllocator> allocator;
gpgmm::d3d12::CreateResourceAllocator(desc, device, adapter, &allocator, &residency);
```

```cpp
D3D12_RESOURCE_DESC& resourceDesc = {};
D3D12_RESOURCE_STATES initialState = {}
gpgmm::d3d12::ALLOCATION_DESC allocationDesc = {};

ComPtr<gpgmm::d3d12::IResourceAllocation> allocation;
allocator->CreateResource(allocationDesc, resourceDesc, initialState, nullptr, &allocation);
```

GPUs do not support page-faulting, so it's up the GPU application to avoid using too much
physical GPU memory. GPGMM integrates residency into the resource allocators to simplify and optimize allocation:

```cpp
ComPtr<gpgmm::d3d12::IResidencyList> list;
CreateResidencyList(&list);
list->Add(allocation->GetMemory());

residency->ExecuteCommandList(&queue, &commandList, &list, 1);

// Prepare for next frame.
list->Reset();
```

Residency also works for non-resources too:

```cpp
gpgmm::d3d12::RESIDENCY_HEAP_DESC shaderVisibleHeap = {};
shaderVisibleHeap.SizeInBytes = kHeapSize;
shaderVisibleHeap.HeapSegment = DXGI_MEMORY_SEGMENT_GROUP_LOCAL;

ComPtr<gpgmm::d3d12::IResidencyHeap> descriptorHeap;
CreateHeapContext createHeapContext(heapDesc);
gpgmm::d3d12::CreateResidencyHeap(shaderVisibleHeap, residencyManager,
      createHeapContext, &CreateHeapContext::CreateHeapCallbackWrapper,
      &descriptorHeap);

// Shader-visible heaps should be locked or always resident.
residency->LockHeap(descriptorHeap.get());
```

To clean-up, simply call `Release()` once the is GPU is finished.

### Vulkan

```cpp
#include <gpgmm_vk.h>

gpgmm::vk::GpAllocatorCreateInfo allocatorInfo = {};

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

# Project integration
Aside from DirectX or Vulkan libraries, **GPGMM has no additional dependencies** when deployed. GPGMM is distributed for use as source-only. It is recommended to use the built-in GN or CMake build targets. Alternatively, a shared library can be built to enable other build systems.

## Source based builds

Allows GPGMM to be added as a source-package dependency to an existing build system.

### GN

BUILD.gn

```gn
source_set("proj") {
  deps = [ "${gpgmm_dir}:src/gpgmm" ]
}
```

Create `build_overrides/gpgmm.gni` file in root directory.

To build with a backend, add the corresponding argument from following table in ``build_overrides/gpgmm.gni`:

| Backend | Build override argument |
|---------|--------------|
| DirectX 12 | `gpgmm_enable_d3d12=true` |
| Vulkan | `gpgmm_enable_vk=true` |

### CMake

CMakeLists.txt

Using CMake 3.14 or newer:

```cmake
include(FetchContent)
FetchContent_Declare(gpgmm
  GIT_REPOSITORY https://github.com/intel/gpgmm.git
  GIT_TAG main
)

# Specify GPGMM build options (see below).
...

FetchContent_MakeAvailable(gpgmm)
```

Or alternatively, manually fetch:

```sh
git clone https://github.com/intel/gpgmm.git third_party/gpgmm
```

And make available:
```cmake
add_subdirectory(third_party/gpgmm)
...

# Specify GPGMM build options (see below).
...
```

Then add:
```cmake
target_link_libraries(proj PRIVATE gpgmm)
```

## Linked-library builds

Allows GPGMM to be built as a library-binary then linked as build-dependency.

### vcpkg (package manager)

First [install vcpkg] then run `install gpgmm`.

[install vcpkg]: https://github.com/microsoft/vcpkg#quick-start-windows

```
vcpkg install gpgmm
```

### GN

Use `is_clang=false gpgmm_shared_library=true` when [Setting up the build](#Setting-up-the-build).
Then use `ninja -C out/Release gpgmm` or `ninja -C out/Debug gpgmm` to build the shared library.

### CMake

```cmake
cmake -DBUILD_SHARED_LIBS=ON -DCMAKE_BUILD_TYPE=Debug .
cmake --build . --config Debug
```

### Visual Studio configuration

1. Copy the DLL into the `$(OutputPath)` folder and configure the VS build:
2. Highlight project in the **Solution Explorer**, and then select **Project > Properties**.
3. Under **Configuration Properties > C/C++ > General**, add `gpgmm\include` to **Additional Include Directories**.
4. Under **Configuration Properties > Linker > Input**, add ``gpgmm.dll.lib`` to **Additional Dependencies**.
5. Under **Configuration Properties > Linker > General**, add the folder path to `out\Release` to **Additional Library Directories**.

# Build and Run

Building GPGMM for development.

## GN

### Install depot_tools and visual studio

GPGMM uses the Chromium build system and dependency management so you need to [install depot_tools] and add it to the PATH. Then [install visual studio] with the SDK and “Debugging Tools For Windows” package.

[install depot_tools]: http://commondatastorage.googleapis.com/chrome-infra-docs/flat/depot_tools/docs/html/depot_tools_tutorial.html#_setting_up
[install visual studio]: https://chromium.googlesource.com/chromium/src/+/HEAD/docs/windows_build_instructions.md#visual-studio

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

### Configure the build
Generate build files using `gn args out/Debug` or `gn args out/Release`.

A text editor will appear asking build arguments, the most common argument is `is_debug=true/false`; otherwise `gn args out/Release --list` shows all the possible options.

### Build

Then use `ninja -C out/Release` or `ninja -C out/Debug` to build.

## CMake

### Install `CMake`

GPGMM uses CMake 3.14 or higher for the build system and dependency management, so you need to [install cmake] and add it to the PATH.

[install cmake]: https://cmake.org/download/

### Configure the build

Generate build files using `cmake . -DCMAKE_BUILD_TYPE=Debug` or `cmake . -DCMAKE_BUILD_TYPE=Release`.

To build with a backend, please specify the corresponding argument from following table.

| Backend | Build argument |
|---------|--------------|
| DirectX 12 | `GPGMM_ENABLE_D3D12=ON` |
| Vulkan | `GPGMM_ENABLE_VK=ON` |

For example, adding `-DGPGMM_ENABLE_VK=OFF` builds without Vulkan.

Additional build options further configure GPGMM:

| Build option | Build argument |
|---------|--------------|
| Disable compilation of tests | `GPGMM_ENABLE_TESTS=OFF` |
| GPGMM is NOT being built in GPGMM repo | `GPGMM_STANDALONE=OFF` |
| Compile GPGMM as shared library | `BUILD_SHARED_LIBS` |

For example, adding `-dGPGMM_STANDALONE=OFF`, and `-dBUILD_SHARED_LIBS` builds GPGMM as a shared DLL.

**Notes**: CMake 3.14 or higher is required for `GPGMM_ENABLE_TESTS` or `GPGMM_ENABLE_VK`.

#### Vulkan-specific

The following build options are only available when `GPGMM_ENABLE_VK=ON`:

| Build option | Build argument |
|---------|--------------|
| Import Vulkan functions statically | `GPGMM_ENABLE_VK_STATIC_FUNCTIONS=ON` |

For example, adding `-dGPGMM_ENABLE_VK_STATIC_FUNCTIONS=ON` will use Vulkan by statically linking functions (from the built-in Vulkan Loader).

### Build

```cmake
cmake --build .
```

# Testing

* Unit tests check the front-end code in isolation or without a GPU.
* End2End tests check both the front AND backend code with a GPU.
* Capture replay checks using pre-recorded memory patterns with a GPU.
* Fuzzer checks using random memory patterns with a GPU.

## GN

```sh
> cd out/Debug # or out/Release
```

### Run unit tests:
```sh
> gpgmm_unittests
```

### Run end2end tests:
```sh
> gpgmm_end2end_tests
```

### Run capture replay tests:
```sh
> gpgmm_capture_replay_tests
```

To re-generate the capture:
```sh
gpgmm_capture_replay_tests.exe --gtest_filter=*Replay/* --event-mask=0x3 --disable-memory-playback
```

### Run fuzzing tests:
```sh
> gpgmm_*_fuzzer  -max_total_time=<seconds_to_run>
```

## CMake

```sh
> cd Debug # or Release
```

### Run ALL tests (after build)

```sh
> cmake --build . --target RUN_TESTS
```

## License

Apache 2.0 Public License, please see [LICENSE](/LICENSE).
