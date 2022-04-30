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
//

#include "tests/capture_replay_tests/GPGMMCaptureReplayTests.h"

#include "gpgmm/TraceEventPhase.h"
#include "gpgmm/d3d12/UtilsD3D12.h"
#include "gpgmm/utils/Log.h"
#include "gpgmm/utils/PlatformTime.h"
#include "tests/D3D12Test.h"

#include <fstream>
#include <string>
#include <unordered_map>

#include <gpgmm_d3d12.h>
#include <json/json.h>

using namespace gpgmm::d3d12;

namespace {

    ALLOCATION_DESC ConvertToAllocationDesc(const Json::Value& allocationDescriptorJsonValue) {
        ALLOCATION_DESC allocationDescriptor = {};
        allocationDescriptor.Flags =
            static_cast<ALLOCATION_FLAGS>(allocationDescriptorJsonValue["Flags"].asInt());
        allocationDescriptor.HeapType =
            static_cast<D3D12_HEAP_TYPE>(allocationDescriptorJsonValue["HeapType"].asInt());
        return allocationDescriptor;
    }

    D3D12_CLEAR_VALUE ConvertToD3D12ClearValue(const Json::Value& clearValueJsonValue) {
        D3D12_CLEAR_VALUE clearValue = {};
        clearValue.Format = static_cast<DXGI_FORMAT>(clearValueJsonValue["Format"].asInt());
        if (IsDepthFormat(clearValue.Format)) {
            const Json::Value& depthStencilValue = clearValueJsonValue["DepthStencil"];
            clearValue.DepthStencil.Depth = depthStencilValue["Depth"].asFloat();
            clearValue.DepthStencil.Stencil = depthStencilValue["Stencil"].asUInt();
        } else {
            const Json::Value& rgba = clearValueJsonValue["Color"];
            clearValue.Color[0] = rgba["R"].asFloat();
            clearValue.Color[1] = rgba["G"].asFloat();
            clearValue.Color[2] = rgba["B"].asFloat();
            clearValue.Color[3] = rgba["A"].asFloat();
        }
        return clearValue;
    }

    D3D12_RESOURCE_DESC ConvertToD3D12ResourceDesc(const Json::Value& resourceDescriptorJsonValue) {
        D3D12_RESOURCE_DESC resourceDescriptor = {};
        resourceDescriptor.Dimension =
            static_cast<D3D12_RESOURCE_DIMENSION>(resourceDescriptorJsonValue["Dimension"].asInt());
        resourceDescriptor.Alignment = resourceDescriptorJsonValue["Alignment"].asUInt64();
        resourceDescriptor.Width = resourceDescriptorJsonValue["Width"].asUInt64();
        resourceDescriptor.Height = resourceDescriptorJsonValue["Height"].asUInt();
        resourceDescriptor.DepthOrArraySize =
            resourceDescriptorJsonValue["DepthOrArraySize"].asUInt();
        resourceDescriptor.MipLevels = resourceDescriptorJsonValue["MipLevels"].asUInt();

        const Json::Value& resourceDescriptorSampleDescJsonValue =
            resourceDescriptorJsonValue["SampleDesc"];

        resourceDescriptor.SampleDesc.Count =
            resourceDescriptorSampleDescJsonValue["Count"].asUInt();
        resourceDescriptor.SampleDesc.Quality =
            resourceDescriptorSampleDescJsonValue["Quality"].asUInt();

        resourceDescriptor.Format =
            static_cast<DXGI_FORMAT>(resourceDescriptorJsonValue["Format"].asInt());
        resourceDescriptor.Layout =
            static_cast<D3D12_TEXTURE_LAYOUT>(resourceDescriptorJsonValue["Layout"].asInt());
        resourceDescriptor.Flags =
            static_cast<D3D12_RESOURCE_FLAGS>(resourceDescriptorJsonValue["Flags"].asInt());

        return resourceDescriptor;
    }

    bool IsErrorEvent(const Json::Value& args) {
        return (args.isMember("Description") && args.isMember("ID"));
    }

}  // namespace

class D3D12EventTraceReplay : public D3D12TestBase, public CaptureReplayTestWithParams {
  protected:
    void SetUp() override {
        D3D12TestBase::SetUp();
    }

    void TearDown() override {
        D3D12TestBase::TearDown();
    }

    void RunTest(const TraceFile& traceFile,
                 const TestEnviromentParams& envParams,
                 const uint64_t iterationIndex) override {
        std::ifstream traceFileStream(traceFile.path, std::ifstream::binary);

        Json::Value root;
        Json::Reader reader;
        ASSERT_TRUE(reader.parse(traceFileStream, root, false));

        std::unordered_map<std::string, RESOURCE_ALLOCATION_INFO> allocationInfoToID;
        std::unordered_map<std::string, HEAP_INFO> heapInfoToID;

        ComPtr<ResourceAllocation> allocationWithoutID;

        std::unordered_map<std::string, ComPtr<ResourceAllocator>> allocatorToID;
        std::unordered_map<std::string, ComPtr<ResourceAllocation>> allocationToID;

        std::string currentAllocatorID;

        const Json::Value& traceEvents = root["traceEvents"];
        ASSERT_TRUE(!traceEvents.empty());

        for (Json::Value::ArrayIndex eventIndex = 0; eventIndex < traceEvents.size();
             eventIndex++) {
            const Json::Value& event = traceEvents[eventIndex];
            if (event["name"].asString() == "ResourceAllocator.CreateResource") {
                switch (*event["ph"].asCString()) {
                    case TRACE_EVENT_PHASE_INSTANT: {
                        const Json::Value& args = event["args"];
                        ASSERT_FALSE(args.empty());

                        // TODO: Consider encoding type instead of checking fields.
                        if (IsErrorEvent(args)) {
                            continue;
                        }

                        // Imported resources cannot be used for playback.
                        if (args["allocationDescriptor"].empty()) {
                            continue;
                        }

                        ALLOCATION_DESC allocationDescriptor =
                            ConvertToAllocationDesc(args["allocationDescriptor"]);

                        const D3D12_RESOURCE_STATES initialResourceState =
                            static_cast<D3D12_RESOURCE_STATES>(
                                args["initialResourceState"].asInt());

                        const D3D12_CLEAR_VALUE* clearValuePtr = nullptr;
                        D3D12_CLEAR_VALUE clearValue = {};
                        const Json::Value& clearValueJsonValue = args["clearValue"];
                        if (!clearValueJsonValue.empty()) {
                            clearValue = ConvertToD3D12ClearValue(clearValueJsonValue);
                            clearValuePtr = &clearValue;
                        }

                        const D3D12_RESOURCE_DESC resourceDescriptor =
                            ConvertToD3D12ResourceDesc(args["resourceDescriptor"]);

                        auto it = allocatorToID.find(currentAllocatorID);
                        ASSERT_TRUE(it != allocatorToID.end());

                        ResourceAllocator* resourceAllocator =
                            allocatorToID[currentAllocatorID].Get();
                        ASSERT_NE(resourceAllocator, nullptr);

                        if (envParams.IsNeverAllocate) {
                            allocationDescriptor.Flags |= ALLOCATION_FLAG_NEVER_ALLOCATE_MEMORY;
                        }

                        mPlatformTime->StartElapsedTime();

                        HRESULT hr = resourceAllocator->CreateResource(
                            allocationDescriptor, resourceDescriptor, initialResourceState,
                            clearValuePtr, &allocationWithoutID);

                        const double elapsedTime = mPlatformTime->EndElapsedTime();

                        if (!envParams.IsNeverAllocate && FAILED(hr)) {
                            gpgmm::ErrorLog() << "CreateResource failed with :" << args << ".\n";
                        }

                        ASSERT_SUCCEEDED(hr);

                        mReplayedAllocationStats.CurrentUsage += allocationWithoutID->GetSize();
                        mReplayedAllocationStats.PeakUsage =
                            std::max(mReplayedAllocationStats.CurrentUsage,
                                     mReplayedAllocationStats.PeakUsage);
                        mReplayedAllocationStats.TotalCount++;
                        mReplayedAllocationStats.TotalSize += allocationWithoutID->GetSize();

                        mReplayedAllocateStats.TotalCpuTime += elapsedTime;
                        mReplayedAllocateStats.PeakCpuTime =
                            std::max(elapsedTime, mReplayedAllocateStats.PeakCpuTime);
                        mReplayedAllocateStats.TotalNumOfCalls++;

                    } break;

                    default:
                        break;
                }
            } else if (event["name"].asString() == "GPUMemoryAllocation") {
                switch (*event["ph"].asCString()) {
                    case TRACE_EVENT_PHASE_SNAPSHOT_OBJECT: {
                        const std::string& allocationID = event["id"].asString();
                        if (allocationInfoToID.find(allocationID) != allocationInfoToID.end()) {
                            continue;
                        }

                        const Json::Value& snapshot = event["args"]["snapshot"];

                        RESOURCE_ALLOCATION_INFO allocationDesc = {};
                        allocationDesc.SizeInBytes = snapshot["SizeInBytes"].asUInt64();
                        allocationDesc.HeapOffset = snapshot["HeapOffset"].asUInt64();
                        allocationDesc.OffsetFromResource =
                            snapshot["OffsetFromResource"].asUInt64();
                        allocationDesc.Method =
                            static_cast<gpgmm::AllocationMethod>(snapshot["Method"].asInt());

                        mCapturedAllocationStats.TotalSize += allocationDesc.SizeInBytes;
                        mCapturedAllocationStats.TotalCount++;
                        mCapturedAllocationStats.CurrentUsage += allocationDesc.SizeInBytes;
                        mCapturedAllocationStats.PeakUsage =
                            std::max(mCapturedAllocationStats.PeakUsage,
                                     mCapturedAllocationStats.CurrentUsage);

                        ASSERT_TRUE(
                            allocationInfoToID.insert({allocationID, allocationDesc}).second);
                    } break;

                    case TRACE_EVENT_PHASE_CREATE_OBJECT: {
                        if (allocationWithoutID == nullptr) {
                            continue;
                        }

                        ASSERT_TRUE(allocationWithoutID != nullptr);
                        const std::string& allocationID = event["id"].asString();
                        ASSERT_TRUE(
                            allocationToID.insert({allocationID, allocationWithoutID}).second);

                        ASSERT_TRUE(allocationWithoutID.Reset() == 1);
                    } break;

                    case TRACE_EVENT_PHASE_DELETE_OBJECT: {
                        const std::string& allocationID = event["id"].asString();

                        auto it = allocationInfoToID.find(allocationID);
                        if (it == allocationInfoToID.end()) {
                            continue;
                        }

                        const RESOURCE_ALLOCATION_INFO& allocationDesc = it->second;
                        mCapturedAllocationStats.CurrentUsage -= allocationDesc.SizeInBytes;

                        ASSERT_EQ(allocationInfoToID.erase(allocationID), 1u);

                        if (allocationToID.find(allocationID) == allocationToID.end()) {
                            continue;
                        }

                        mReplayedAllocationStats.CurrentUsage -=
                            allocationToID[allocationID]->GetSize();

                        mPlatformTime->StartElapsedTime();

                        const bool didDeallocate = allocationToID.erase(allocationID);

                        const double elapsedTime = mPlatformTime->EndElapsedTime();

                        ASSERT_TRUE(didDeallocate || envParams.IsNeverAllocate);

                        mReplayedDeallocateStats.TotalCpuTime += elapsedTime;
                        mReplayedDeallocateStats.PeakCpuTime =
                            std::max(elapsedTime, mReplayedDeallocateStats.PeakCpuTime);
                        mReplayedDeallocateStats.TotalNumOfCalls++;

                    } break;

                    default:
                        break;
                }
            } else if (event["name"].asString() == "GPUMemoryAllocator") {
                switch (*event["ph"].asCString()) {
                    case TRACE_EVENT_PHASE_SNAPSHOT_OBJECT: {
                        const std::string& allocatorID = event["id"].asString();
                        if (allocatorToID.find(allocatorID) != allocatorToID.end()) {
                            continue;
                        }

                        const Json::Value& snapshot = event["args"]["snapshot"];
                        ASSERT_FALSE(snapshot.empty());

                        // Apply profile (if specified).
                        ALLOCATOR_DESC allocatorDesc =
                            CreateBasicAllocatorDesc(/*enablePrefetch*/ envParams.PrefetchMemory);
                        if (envParams.AllocatorProfile ==
                            AllocatorProfile::ALLOCATOR_PROFILE_CAPTURED) {
                            allocatorDesc.Flags |=
                                static_cast<ALLOCATOR_FLAGS>(snapshot["Flags"].asInt());
                            allocatorDesc.PreferredResourceHeapSize =
                                snapshot["PreferredResourceHeapSize"].asUInt64();
                            allocatorDesc.MaxResourceHeapSize =
                                snapshot["MaxResourceHeapSize"].asUInt64();
                            allocatorDesc.MaxVideoMemoryBudget =
                                snapshot["MaxVideoMemoryBudget"].asFloat();
                            allocatorDesc.TotalResourceBudgetLimit =
                                snapshot["TotalResourceBudgetLimit"].asUInt64();
                            allocatorDesc.EvictLimit = snapshot["EvictLimit"].asUInt64();
                            allocatorDesc.MemoryFragmentationLimit =
                                snapshot["MemoryFragmentationLimit"].asDouble();
                        } else if (envParams.AllocatorProfile ==
                                   AllocatorProfile::ALLOCATOR_PROFILE_MAX_PERFORMANCE) {
                            // Any amount of (internal) fragmentation is acceptable.
                            allocatorDesc.MemoryFragmentationLimit = 1.0f;
                        } else if (envParams.AllocatorProfile ==
                                   AllocatorProfile::ALLOCATOR_PROFILE_LOW_MEMORY) {
                            allocatorDesc.Flags |= ALLOCATOR_FLAG_ALWAYS_ON_DEMAND;
                            allocatorDesc.MemoryFragmentationLimit = 0.125;  // 1/8th of 4MB
                        }

                        if (envParams.IsStandaloneOnly) {
                            allocatorDesc.Flags |= ALLOCATOR_FLAG_ALWAYS_COMMITED;
                        }

                        if (envParams.IsRegenerate) {
                            allocatorDesc.RecordOptions.Flags = ALLOCATOR_RECORD_FLAG_CAPTURE;
                            allocatorDesc.RecordOptions.TraceFile = traceFile.path;
                            allocatorDesc.RecordOptions.MinMessageLevel =
                                static_cast<ALLOCATOR_MESSAGE_SEVERITY>(envParams.RecordLevel);

                            // Keep recording across multiple playback iterations to ensure all
                            // events will be captured instead of overwritten per iteration.
                            if (envParams.Iterations == 1) {
                                allocatorDesc.RecordOptions.EventScope =
                                    ALLOCATOR_RECORD_SCOPE_PER_INSTANCE;
                            }
                        }

                        allocatorDesc.MinLogLevel =
                            static_cast<ALLOCATOR_MESSAGE_SEVERITY>(envParams.LogLevel);

                        if (envParams.LogLevel <= gpgmm::LogSeverity::Warning &&
                            allocatorDesc.IsUMA != snapshot["IsUMA"].asBool() &&
                            iterationIndex == 0) {
                            gpgmm::WarningLog()
                                << "Capture device does not match playback device (IsUMA: " +
                                       std::to_string(snapshot["IsUMA"].asBool()) + " vs " +
                                       std::to_string(allocatorDesc.IsUMA) + ").";
                            GPGMM_SKIP_TEST_IF(envParams.IsCapturedCapsCompat);
                        }

                        if (envParams.LogLevel <= gpgmm::LogSeverity::Warning &&
                            allocatorDesc.ResourceHeapTier !=
                                snapshot["ResourceHeapTier"].asInt() &&
                            iterationIndex == 0) {
                            gpgmm::WarningLog()
                                << "Capture device does not match playback device "
                                   "(ResourceHeapTier: " +
                                       std::to_string(snapshot["ResourceHeapTier"].asInt()) +
                                       " vs " + std::to_string(allocatorDesc.ResourceHeapTier) +
                                       ").";
                            GPGMM_SKIP_TEST_IF(envParams.IsCapturedCapsCompat);
                        }

                        ComPtr<ResourceAllocator> resourceAllocator;
                        ASSERT_SUCCEEDED(
                            ResourceAllocator::CreateAllocator(allocatorDesc, &resourceAllocator));

                        ASSERT_TRUE(
                            allocatorToID.insert({allocatorID, std::move(resourceAllocator)})
                                .second);
                    } break;

                    case TRACE_EVENT_PHASE_CREATE_OBJECT: {
                        // Assume subsequent events are always against this allocator instance.
                        // This is because call trace events have no ID associated with them.
                        currentAllocatorID = event["id"].asString();
                    } break;

                    case TRACE_EVENT_PHASE_DELETE_OBJECT: {
                        const std::string& allocatorID = event["id"].asString();

                        auto it = allocatorToID.find(allocatorID);
                        ASSERT_TRUE(it != allocatorToID.end());
                        ASSERT_EQ(allocatorToID.erase(allocatorID), 1u);
                    } break;

                    default:
                        break;
                }
            } else if (event["name"].asString() == "GPUMemoryBlock") {
                switch (*event["ph"].asCString()) {
                    case TRACE_EVENT_PHASE_SNAPSHOT_OBJECT: {
                        const std::string& heapID = event["id"].asString();
                        if (heapInfoToID.find(heapID) != heapInfoToID.end()) {
                            continue;
                        }

                        const Json::Value& snapshot = event["args"]["snapshot"];

                        HEAP_INFO heapInfo = {};
                        heapInfo.IsResident = snapshot["IsResident"].asBool();
                        heapInfo.MemorySegmentGroup = static_cast<DXGI_MEMORY_SEGMENT_GROUP>(
                            snapshot["MemorySegmentGroup"].asInt());
                        heapInfo.SizeInBytes = snapshot["SizeInBytes"].asUInt64();

                        mCapturedMemoryStats.TotalSize += heapInfo.SizeInBytes;
                        mCapturedMemoryStats.TotalCount++;
                        mCapturedMemoryStats.CurrentUsage += heapInfo.SizeInBytes;
                        mCapturedMemoryStats.PeakUsage = std::max(
                            mCapturedMemoryStats.PeakUsage, mCapturedMemoryStats.CurrentUsage);

                        ASSERT_TRUE(heapInfoToID.insert({heapID, heapInfo}).second);
                    } break;

                    case TRACE_EVENT_PHASE_DELETE_OBJECT: {
                        const std::string& traceEventID = event["id"].asString();
                        auto it = heapInfoToID.find(traceEventID);
                        ASSERT_TRUE(it != heapInfoToID.end());

                        HEAP_INFO heapInfo = it->second;
                        mCapturedMemoryStats.CurrentUsage -= heapInfo.SizeInBytes;

                        ASSERT_EQ(heapInfoToID.erase(traceEventID), 1u);

                    } break;

                    default:
                        break;
                }
            }
        }

        EXPECT_TRUE(allocationInfoToID.empty());
        EXPECT_TRUE(allocatorToID.empty());
        EXPECT_TRUE(heapInfoToID.empty());
    }

    CaptureReplayCallStats mReplayedAllocateStats;
    CaptureReplayCallStats mReplayedDeallocateStats;
    CaptureReplayMemoryStats mReplayedAllocationStats;

    CaptureReplayMemoryStats mCapturedAllocationStats;
    CaptureReplayMemoryStats mCapturedMemoryStats;
};

TEST_P(D3D12EventTraceReplay, AllocationPerf) {
    RunTestLoop(/*forceRegenerate*/ false, /*forceIsCapturedCapsCompat*/ false,
                /*forceSingleIteration*/ false, /*forcePrefetchMemory*/ true);

    LogCallStats("Allocation(s)", mReplayedAllocateStats);
    LogCallStats("Deallocation(s)", mReplayedDeallocateStats);
}

// Verify captured does not regress (ie. consume more memory) upon playback.
TEST_P(D3D12EventTraceReplay, MemoryUsage) {
    RunSingleTest(/*forceRegenerate*/ false, /*forceIsCapturedCapsCompat*/ true,
                  /*forcePrefetchMemory*/ false);

    LogMemoryStats("Allocation", mCapturedAllocationStats);
    LogMemoryStats("Memory", mCapturedMemoryStats);

    EXPECT_LE(mReplayedAllocationStats.TotalSize, mCapturedAllocationStats.TotalSize);
    EXPECT_LE(mReplayedAllocationStats.PeakUsage, mCapturedAllocationStats.PeakUsage);
    EXPECT_EQ(mReplayedAllocationStats.TotalCount, mCapturedAllocationStats.TotalCount);
}

// Re-generates traces.
TEST_P(D3D12EventTraceReplay, Regenerate) {
    RunSingleTest(/*forceRegenerate*/ true, /*forceIsCapturedCapsCompat*/ false,
                  /*forcePrefetchMemory*/ false);
}

GPGMM_INSTANTIATE_CAPTURE_REPLAY_TEST(D3D12EventTraceReplay);
