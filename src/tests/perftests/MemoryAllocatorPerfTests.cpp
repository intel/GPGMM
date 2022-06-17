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

#include <benchmark/benchmark.h>

#include "gpgmm/common/BuddyMemoryAllocator.h"
#include "gpgmm/common/SlabMemoryAllocator.h"
#include "gpgmm/common/StandaloneMemoryAllocator.h"
#include "tests/DummyMemoryAllocator.h"

using namespace gpgmm;

static constexpr uint64_t kMemoryAlignment = 1;

class MemoryAllocatorPerfTests : public benchmark::Fixture {
  public:
    MEMORY_ALLOCATION_REQUEST CreateBasicRequest(uint64_t size, uint64_t alignment = 1) {
        MEMORY_ALLOCATION_REQUEST request = {};
        request.SizeInBytes = size;
        request.Alignment = alignment;
        request.NeverAllocate = false;
        request.AlwaysCacheSize = false;
        request.AlwaysPrefetch = false;
        request.AvailableForAllocation = kInvalidSize;
        return request;
    }
};

BENCHMARK_DEFINE_F(MemoryAllocatorPerfTests, SlabCache_Warm)(benchmark::State& state) {
    SlabCacheAllocator allocator(
        state.range(1), state.range(0), kMemoryAlignment, kMemoryAlignment, /*allowPrefetch*/ false,
        /*kNoSlabGrowthFactor*/ 1, std::make_unique<DummyMemoryAllocator>());

    // Below is effectively equivelent to STL's reserve(size=1).
    {
        MEMORY_ALLOCATION_REQUEST request = CreateBasicRequest(state.range(2));
        request.AlwaysCacheSize = true;
        request.NeverAllocate = true;
        allocator.TryAllocateMemory(request);
    }

    for (auto _ : state) {
        auto alloc = allocator.TryAllocateMemory(CreateBasicRequest(state.range(2)));
        if (alloc == nullptr) {
            state.SkipWithError("Unable to allocate. Skipping.");
            break;
        }
        allocator.DeallocateMemory(std::move(alloc));
    }
}

BENCHMARK_DEFINE_F(MemoryAllocatorPerfTests, SlabCache_Cold)(benchmark::State& state) {
    SlabCacheAllocator allocator(state.range(1), state.range(0), kMemoryAlignment,
                                 /*slabFragmentationLimit*/ 1, /*allowPrefetch*/ false,
                                 /*kNoSlabGrowthFactor*/ 1,
                                 std::make_unique<DummyMemoryAllocator>());

    for (auto _ : state) {
        auto alloc = allocator.TryAllocateMemory(CreateBasicRequest(state.range(2)));
        if (alloc == nullptr) {
            state.SkipWithError("Unable to allocate. Skipping.");
            break;
        }
        allocator.DeallocateMemory(std::move(alloc));
    }
}

BENCHMARK_DEFINE_F(MemoryAllocatorPerfTests, Slab)(benchmark::State& state) {
    std::unique_ptr<DummyMemoryAllocator> memoryAllocator =
        std::make_unique<DummyMemoryAllocator>();
    SlabMemoryAllocator allocator(state.range(2), state.range(1), state.range(0), kMemoryAlignment,
                                  /*slabFragmentationLimit*/ 1, /*allowPrefetch*/ false,
                                  /*slabGrowthFactor*/ 1, memoryAllocator.get());

    for (auto _ : state) {
        auto alloc = allocator.TryAllocateMemory(CreateBasicRequest(state.range(2)));
        if (alloc == nullptr) {
            state.SkipWithError("Unable to allocate. Skipping.");
            break;
        }
        allocator.DeallocateMemory(std::move(alloc));
    }
}

BENCHMARK_DEFINE_F(MemoryAllocatorPerfTests, BuddySystem)(benchmark::State& state) {
    BuddyMemoryAllocator allocator(state.range(1), state.range(0), kMemoryAlignment,
                                   std::make_unique<DummyMemoryAllocator>());

    for (auto _ : state) {
        auto alloc = allocator.TryAllocateMemory(CreateBasicRequest(state.range(2)));
        if (alloc == nullptr) {
            state.SkipWithError("Unable to allocate. Skipping.");
            break;
        }
        allocator.DeallocateMemory(std::move(alloc));
    }
}

BENCHMARK_DEFINE_F(MemoryAllocatorPerfTests, Standalone)(benchmark::State& state) {
    StandaloneMemoryAllocator allocator(std::make_unique<DummyMemoryAllocator>());

    for (auto _ : state) {
        auto alloc = allocator.TryAllocateMemory(CreateBasicRequest(state.range(2)));
        if (alloc == nullptr) {
            state.SkipWithError("Unable to allocate. Skipping.");
            break;
        }
        allocator.DeallocateMemory(std::move(alloc));
    }
}

static void GenerateParams(benchmark::internal::Benchmark* benchmark) {
    static constexpr uint64_t kMaxMemorySize = (1ull << 34);  // ~16GB
    static constexpr uint64_t kMinMemorySize = (1ull << 22);  // 4MB

    benchmark->ArgNames({"min", "max", "size"});
    benchmark->Args({kMinMemorySize, kMaxMemorySize, /*256B*/ 256});
    benchmark->Args({kMinMemorySize, kMaxMemorySize, /*64KB*/ 64 * 1024});
    benchmark->Args({kMinMemorySize, kMaxMemorySize, /*4MB*/ 4 * 1024 * 1024});
    benchmark->Args({kMinMemorySize, kMaxMemorySize, /*64MB*/ 64 * 1024 * 1024});
}

// Register each as benchmark
BENCHMARK_REGISTER_F(MemoryAllocatorPerfTests, SlabCache_Warm)->Apply(GenerateParams);
BENCHMARK_REGISTER_F(MemoryAllocatorPerfTests, SlabCache_Cold)->Apply(GenerateParams);
BENCHMARK_REGISTER_F(MemoryAllocatorPerfTests, Slab)->Apply(GenerateParams);
BENCHMARK_REGISTER_F(MemoryAllocatorPerfTests, BuddySystem)->Apply(GenerateParams);
BENCHMARK_REGISTER_F(MemoryAllocatorPerfTests, Standalone)->Apply(GenerateParams);

// Run the benchmarks
BENCHMARK_MAIN();
