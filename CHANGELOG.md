# GPGMM Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

New
- `gpgmm::d3d12::ALLOCATOR_FLAGS::ALLOCATOR_ALWAYS_COMMITED` flag to help troubleshoot problems from using placed resource based sub-allocation.
- `gpgmm::d3d12::ALLOCATOR_FLAGS::ALLOCATOR_ALWAYS_IN_BUDGET` flag to help troubleshoot
problems from over committing when using residency.

- `gpgmm::d3d12::ALLOCATOR_DESC::[PreferredResourceHeapSize|MaxResourceHeapSize]` option(s) to specify the (preferred) min and/or max heap sizes, respectively (vs hard coded).
- `gpgmm::d3d12::ALLOCATOR_DESC::[MaxVideoMemoryBudget|TotalResourceBudgetLimit]` option(s) to specify the app and/or resource memory budget, respectively (vs hard coded).
- `gpgmm::d3d12::ALLOCATOR_DESC::MaxResourceSizeForPooling` option to specify the max pool-allocate heap size (vs hard coded).

Modified
- `gpgmm::BuddyAllocator::DeallocateBlock` has been optimized to avoid Log2(N) search (58eba11879ce8c03d9a7df711cac70ac98217dca).
- `gpgmm::d3d12::ResourceHeapAllocator` calculates placed resource alignment based on heap flags (1b955a62f8d468a9b185e4aa3f970358696c0095).
- Prevent failed sub-allocations from leaking (ee87eb3cdcda6264578daaebeccd87ab7662ac4e).
- Fix possible use-after-free bug in `gpgmm::BuddyAllocator::~BuddyAllocator` (13db8b0233cf9f0f054ed080dc207a108564357f).
- Secure switch statements with default values (08aa60bc1d7df638d5e6767313c3b57464f08819).
- `gpgmm::d3d12::GetResourceAllocationInfo` has been optimized for buffers since they are always 64KB sized-aligned (7fa27066ea035d1216dd0f70aabe44b07a5825b7).
- Improve memory usage in `gpgmm::BuddyMemoryAllocator::AllocateMemory` by tracking per allocated heaps (vs system).
