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

#include <benchmark/benchmark.h>

#include "gpgmm/common/BuddyMemoryAllocator.h"
#include "gpgmm/common/DedicatedMemoryAllocator.h"
#include "gpgmm/common/SegmentedMemoryAllocator.h"
#include "gpgmm/common/SizeClass.h"
#include "gpgmm/common/SlabMemoryAllocator.h"
#include "tests/DummyMemoryAllocator.h"

#include <vector>

using namespace gpgmm;

static constexpr double kDisableSlabGrowth = 1.0;
static constexpr uint64_t kMemoryAlignment = 1;

class MemoryAllocatorPerfTests : public benchmark::Fixture {
  public:
    MemoryAllocationRequest CreateBasicRequest(uint64_t size, uint64_t alignment = 1) {
        MemoryAllocationRequest request = {};
        request.SizeInBytes = size;
        request.Alignment = alignment;
        request.NeverAllocate = false;
        request.AlwaysCacheSize = false;
        request.AlwaysPrefetch = false;
        request.AvailableForAllocation = kInvalidSize;
        return request;
    }
};

// Tests allocates memory of a single size then frees it all.
class SingleSizeAllocationPerfTests : public MemoryAllocatorPerfTests {
  public:
    void SingleStep(benchmark::State& state,
                    MemoryAllocator* allocator,
                    const MemoryAllocationRequest& request) const {
        std::vector<std::unique_ptr<MemoryAllocation>> allocations;
        for (int i = 0; i < state.range(3); i++) {
            auto allocation = allocator->TryAllocateMemoryForTesting(request);
            if (allocation == nullptr) {
                state.SkipWithError("Unable to allocate. Skipping.");
                return;
            }
            allocations.push_back(std::move(allocation));
        }

        for (auto& allocation : allocations) {
            allocator->DeallocateMemory(std::move(allocation));
        }
    }

    static void GenerateParams(benchmark::internal::Benchmark* benchmark) {
        static const uint64_t kMaxMemorySize = GPGMM_GB_TO_BYTES(16);
        static const uint64_t kMinMemorySize = GPGMM_MB_TO_BYTES(4);
        static const uint64_t kNumOfAllocations = 10u;

        benchmark->ArgNames({"min", "max", "size", "count"});
        benchmark->Args({kMinMemorySize, kMaxMemorySize, /*256B*/ 256, kNumOfAllocations});
        benchmark->Args({kMinMemorySize, kMaxMemorySize, GPGMM_KB_TO_BYTES(8), kNumOfAllocations});
        benchmark->Args({kMinMemorySize, kMaxMemorySize, GPGMM_KB_TO_BYTES(64), kNumOfAllocations});
        benchmark->Args({kMinMemorySize, kMaxMemorySize, GPGMM_MB_TO_BYTES(2), kNumOfAllocations});
        benchmark->Args({kMinMemorySize, kMaxMemorySize, GPGMM_MB_TO_BYTES(4), kNumOfAllocations});
        benchmark->Args({kMinMemorySize, kMaxMemorySize, GPGMM_MB_TO_BYTES(64), kNumOfAllocations});
    }
};

BENCHMARK_DEFINE_F(SingleSizeAllocationPerfTests, SlabCache_Warm)(benchmark::State& state) {
    SlabCacheAllocator allocator(
        state.range(1), state.range(0), kMemoryAlignment, kMemoryAlignment, /*allowPrefetch*/ false,
        kDisableSlabGrowth, std::make_unique<DummyMemoryAllocator>());

    // Below is effectively equivelent to STL's reserve(size=1).
    {
        MemoryAllocationRequest request = CreateBasicRequest(state.range(2));
        request.AlwaysCacheSize = true;
        request.NeverAllocate = true;
        allocator.TryAllocateMemory(request);
    }

    for (auto _ : state) {
        SingleStep(state, &allocator, CreateBasicRequest(state.range(2)));
    }
}

BENCHMARK_DEFINE_F(SingleSizeAllocationPerfTests, SlabCache_Cold)(benchmark::State& state) {
    SlabCacheAllocator allocator(state.range(1), state.range(0), kMemoryAlignment,
                                 /*slabFragmentationLimit*/ 1, /*allowPrefetch*/ false,
                                 kDisableSlabGrowth,
                                 std::make_unique<DummyMemoryAllocator>());

    for (auto _ : state) {
        SingleStep(state, &allocator, CreateBasicRequest(state.range(2)));
    }
}

BENCHMARK_DEFINE_F(SingleSizeAllocationPerfTests, Slab)(benchmark::State& state) {
    std::unique_ptr<DummyMemoryAllocator> memoryAllocator =
        std::make_unique<DummyMemoryAllocator>();
    SlabMemoryAllocator allocator(state.range(2), state.range(1), state.range(0), kMemoryAlignment,
                                  /*slabFragmentationLimit*/ 1, /*allowPrefetch*/ false,
                                  /*slabGrowthFactor*/ 1, memoryAllocator.get());

    for (auto _ : state) {
        SingleStep(state, &allocator, CreateBasicRequest(state.range(2)));
    }
}

BENCHMARK_DEFINE_F(SingleSizeAllocationPerfTests, BuddySystem)(benchmark::State& state) {
    BuddyMemoryAllocator allocator(state.range(1), state.range(0), kMemoryAlignment,
                                   std::make_unique<DummyMemoryAllocator>());

    for (auto _ : state) {
        SingleStep(state, &allocator, CreateBasicRequest(state.range(2)));
    }
}

BENCHMARK_DEFINE_F(SingleSizeAllocationPerfTests, Standalone)(benchmark::State& state) {
    DedicatedMemoryAllocator allocator(std::make_unique<DummyMemoryAllocator>());

    for (auto _ : state) {
        SingleStep(state, &allocator, CreateBasicRequest(state.range(2)));
    }
}

BENCHMARK_DEFINE_F(SingleSizeAllocationPerfTests, SegmentedPool)(benchmark::State& state) {
    SegmentedMemoryAllocator allocator(std::make_unique<DummyMemoryAllocator>(), kMemoryAlignment);

    for (auto _ : state) {
        SingleStep(state, &allocator, CreateBasicRequest(state.range(2)));
    }
}

// Register each as benchmark
BENCHMARK_REGISTER_F(SingleSizeAllocationPerfTests, SlabCache_Warm)
    ->Apply(SingleSizeAllocationPerfTests::GenerateParams);
BENCHMARK_REGISTER_F(SingleSizeAllocationPerfTests, SlabCache_Cold)
    ->Apply(SingleSizeAllocationPerfTests::GenerateParams);
BENCHMARK_REGISTER_F(SingleSizeAllocationPerfTests, Slab)
    ->Apply(SingleSizeAllocationPerfTests::GenerateParams);
BENCHMARK_REGISTER_F(SingleSizeAllocationPerfTests, BuddySystem)
    ->Apply(SingleSizeAllocationPerfTests::GenerateParams);
BENCHMARK_REGISTER_F(SingleSizeAllocationPerfTests, Standalone)
    ->Apply(SingleSizeAllocationPerfTests::GenerateParams);
BENCHMARK_REGISTER_F(SingleSizeAllocationPerfTests, SegmentedPool)
    ->Apply(SingleSizeAllocationPerfTests::GenerateParams);

// Run the benchmarks
BENCHMARK_MAIN();
