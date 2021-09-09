[![Windows Clang 64-bit Release](https://github.com/intel/GPGMM/actions/workflows/win_clang_rel_x64.yaml/badge.svg)](https://github.com/intel/GPGMM/actions/workflows/win_clang_rel_x64.yaml)
[![Windows Dawn Release](https://github.com/intel/GPGMM/actions/workflows/win_dawn_rel.yaml/badge.svg)](https://github.com/intel/GPGMM/actions/workflows/win_dawn_rel.yaml)

# GPGMM

GPGMM is a General-Purpose GPU Memory Management library.

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

A text editor will appear asking build options, the most common option is `is_debug=true/false`; otherwise `gn args out/Release --list` shows all the possible options.

To build with a backend, please set the corresponding option from following table.

| Backend | Option |
|---------|--------------|
| D3D12 | `gpgmm_enable_d3d12=true` (default on winos) |
| Vulkan | `gpgmm_enable_vulkan=true` |

### Build

Then use `ninja -C out/Release` or `ninja -C out/Debug` to build.

### Run tests

Run unit tests:
```sh
> ./out/Debug/gpgmm_unittests
```

Run end2end tests:
```sh
> ./out/Release/gpgmm_end2end_tests
```

Or through existing project's end2end tests:

```sh
> cp scripts/<project>.gclient .gclient
```

Then `gclient sync` and [build again](#build) before running:

```sh
> out/Debug/<project>_end2end_tests
```

## How do I use it?

To allocate, you create an allocator then create allocations from it:
```cpp
D3D12_FEATURE_DATA_ARCHITECTURE arch = {};
device->CheckFeatureSupport(D3D12_FEATURE_ARCHITECTURE, &arch, sizeof(arch)

D3D12_FEATURE_DATA_D3D12_OPTIONS options = {};
device->CheckFeatureSupport(D3D12_FEATURE_D3D12_OPTIONS, &options, sizeof(options)));

gpgmm::d3d12::ALLOCATOR_DESC allocatorDesc = {};
allocatorDesc.Adapter = adapter;
allocatorDesc.Device = device;
allocatorDesc.IsUMA =  arch.UMA;
allocatorDesc.ResourceHeapTier = options.ResourceHeapTier;
gpgmm::d3d12::ResourceAllocator allocator(desc);
```

```cpp
/* Fill this stuff out */
D3D12_RESOURCE_DESC& resourceDescriptor = {...};
D3D12_RESOURCE_STATES initialState = {...}
D3D12_CLEAR_VALUE zero{};

gpgmm::d3d12::ALLOCATION_DESC allocationDesc = {};
allocationDesc.HeapType = heapType;

ComPtr<gpgmm::d3d12::ResourceAllocation> allocation;
allocator->CreateResource(allocationDesc, resourceDescriptor, initialState, &zero, &allocation);
```

Then de-allocate:
```cpp
/* Must make sure GPU is finished using it */
allocation.Release();
```

To use basic residency:
1. Create a `d3d12::ResourceAllocator` with `ALLOCATOR_ALWAYS_IN_BUDGET` flag.
2. Use `d3d12::ResourceAllocator::CreateResource` for every resource you want residency managed.
3. Create a `d3d12::ResidencySet` to track a collection of allocations that should be resident for a given command-list (1:1 relationship).
4. `d3d12::ResourceAllocation::UpdateResidency` tracks the underlying heap for the resident set.
5. Use `d3d12::ResidencyManager::ExecuteCommandLists` with the residency set, queue, and command list.

What about residency for other heaps (SV descriptor or query heaps)?
1. Sub-class `d3d12::Heap`.
2. Call `d3d12::ResidencyManager::InsertHeap` on it after creation.
3. Use `d3d12::ResidencyManager::Lock` or `d3d12::ResidencyManager::UnlockHeap` to keep heap resident or not, respectively.

# Prerequisites
* Error handing uses API error codes (`HRESULT` and `VkResult` for D3D12 and Vulkan, respectively).
* `d3d12::ResourceAllocation` is ref-counted.

## License

Apache 2.0 Public License, please see [LICENSE](/LICENSE).
