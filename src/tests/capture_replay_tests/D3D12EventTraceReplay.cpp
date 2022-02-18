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

#include "gpgmm/TraceEvent.h"
#include "gpgmm/common/Log.h"
#include "gpgmm/common/PlatformTime.h"
#include "gpgmm/d3d12/UtilsD3D12.h"
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

        std::unordered_map<std::string, RESOURCE_ALLOCATION_DESC> allocationToIDMap;
        std::unordered_map<std::string, HEAP_DESC> heapDescToIDMap;

        ComPtr<ResourceAllocation> newAllocationWithoutID;

        std::unordered_map<std::string, ComPtr<ResourceAllocator>> allocatorToIDMap;
        std::unordered_map<std::string, ComPtr<ResourceAllocation>> newAllocationToIDMap;

        std::string allocatorInstanceID;

        // Apply profile defaults (if specified).
        ALLOCATOR_DESC allocatorDesc = CreateBasicAllocatorDesc();
        if (envParams.AllocatorProfile == AllocatorProfile::ALLOCATOR_PROFILE_MAX_PERFORMANCE) {
            // Pool-allocate everything. Reuse is possible by recycling heaps and sub-allocation.
            allocatorDesc.MaxResourceHeapSize = 32ll * 1024ll * 1024ll * 1024ll;  // 32GB
            allocatorDesc.MaxResourceSizeForPooling = allocatorDesc.MaxResourceHeapSize;

            // Any amount of internal fragment is acceptable.
            allocatorDesc.ResourceFragmentationLimit = 1.0f;

        } else if (envParams.AllocatorProfile == AllocatorProfile::ALLOCATOR_PROFILE_LOW_MEMORY) {
            // Do not pool allocate. Reuse is only possible through sub-allocation.
            allocatorDesc.MaxResourceSizeForPooling = 0;

            allocatorDesc.ResourceFragmentationLimit = 0.125;  // 1/8th of 4MB
        }

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

                        auto it = allocatorToIDMap.find(allocatorInstanceID);
                        ASSERT_TRUE(it != allocatorToIDMap.end());

                        ResourceAllocator* resourceAllocator =
                            allocatorToIDMap[allocatorInstanceID].Get();
                        ASSERT_NE(resourceAllocator, nullptr);

                        if (envParams.IsNeverAllocate) {
                            allocationDescriptor.Flags |= ALLOCATION_FLAG_NEVER_ALLOCATE_MEMORY;
                        }

                        mPlatformTime->StartElapsedTime();

                        HRESULT hr = resourceAllocator->CreateResource(
                            allocationDescriptor, resourceDescriptor, initialResourceState,
                            clearValuePtr, &newAllocationWithoutID);

                        const double elapsedTime = mPlatformTime->EndElapsedTime();

                        ASSERT_TRUE(SUCCEEDED(hr) || envParams.IsNeverAllocate);

                        mReplayedAllocationStats.CurrentUsage += newAllocationWithoutID->GetSize();
                        mReplayedAllocationStats.PeakUsage =
                            std::max(mReplayedAllocationStats.CurrentUsage,
                                     mReplayedAllocationStats.PeakUsage);
                        mReplayedAllocationStats.TotalCount++;
                        mReplayedAllocationStats.TotalSize += newAllocationWithoutID->GetSize();

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
                        if (allocationToIDMap.find(allocationID) != allocationToIDMap.end()) {
                            continue;
                        }

                        const Json::Value& snapshot = event["args"]["snapshot"];

                        RESOURCE_ALLOCATION_DESC allocationDesc = {};
                        allocationDesc.Size = snapshot["Size"].asUInt64();
                        allocationDesc.HeapOffset = snapshot["HeapOffset"].asUInt64();
                        allocationDesc.OffsetFromResource =
                            snapshot["OffsetFromResource"].asUInt64();
                        allocationDesc.Method =
                            static_cast<gpgmm::AllocationMethod>(snapshot["Method"].asInt());

                        mCapturedAllocationStats.TotalSize += allocationDesc.Size;
                        mCapturedAllocationStats.TotalCount++;
                        mCapturedAllocationStats.CurrentUsage += allocationDesc.Size;
                        mCapturedAllocationStats.PeakUsage =
                            std::max(mCapturedAllocationStats.PeakUsage,
                                     mCapturedAllocationStats.CurrentUsage);

                        ASSERT_TRUE(
                            allocationToIDMap.insert({allocationID, allocationDesc}).second);
                    } break;

                    case TRACE_EVENT_PHASE_CREATE_OBJECT: {
                        if (newAllocationWithoutID == nullptr) {
                            ASSERT_TRUE(envParams.IsNeverAllocate);
                            continue;
                        }

                        ASSERT_TRUE(newAllocationWithoutID != nullptr);
                        const std::string& allocationID = event["id"].asString();
                        ASSERT_TRUE(
                            newAllocationToIDMap.insert({allocationID, newAllocationWithoutID})
                                .second);

                        ASSERT_TRUE(newAllocationWithoutID.Reset() == 1);
                    } break;

                    case TRACE_EVENT_PHASE_DELETE_OBJECT: {
                        const std::string& allocationID = event["id"].asString();

                        auto it = allocationToIDMap.find(allocationID);
                        ASSERT_TRUE(it != allocationToIDMap.end());

                        const RESOURCE_ALLOCATION_DESC& allocationDesc = it->second;
                        mCapturedAllocationStats.CurrentUsage -= allocationDesc.Size;

                        ASSERT_EQ(allocationToIDMap.erase(allocationID), 1u);

                        ASSERT_TRUE(newAllocationToIDMap.find(allocationID) !=
                                    newAllocationToIDMap.end());

                        mReplayedAllocationStats.CurrentUsage -=
                            newAllocationToIDMap[allocationID]->GetSize();

                        mPlatformTime->StartElapsedTime();

                        const bool didDeallocate = newAllocationToIDMap.erase(allocationID);

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
                    case TRACE_EVENT_PHASE_INSTANT: {
                        const Json::Value& args = event["args"];
                        ASSERT_FALSE(args.empty());

                        allocatorDesc.Flags = static_cast<ALLOCATOR_FLAGS>(args["Flags"].asInt());
                        if (envParams.IsStandaloneOnly) {
                            allocatorDesc.Flags =
                                allocatorDesc.Flags | ALLOCATOR_FLAG_ALWAYS_COMMITED;
                        }

                        const Json::Value& recordOptions = args["RecordOptions"];
                        ASSERT_FALSE(recordOptions.empty());

                        if (envParams.IsRegenerate) {
                            allocatorDesc.RecordOptions.Flags = ALLOCATOR_RECORD_FLAG_CAPTURE;
                            allocatorDesc.RecordOptions.TraceFile = traceFile.path;
                            allocatorDesc.RecordOptions.MinLogLevel =
                                static_cast<ALLOCATOR_MESSAGE_SEVERITY>(envParams.RecordLevel);
                        }

                        allocatorDesc.MinLogLevel =
                            static_cast<ALLOCATOR_MESSAGE_SEVERITY>(envParams.LogLevel);

                        if (envParams.LogLevel <= gpgmm::LogSeverity::Warning &&
                            allocatorDesc.IsUMA != args["IsUMA"].asBool() && iterationIndex == 0) {
                            gpgmm::WarningLog()
                                << "Capture device does not match playback device (IsUMA: " +
                                       std::to_string(args["IsUMA"].asBool()) + " vs " +
                                       std::to_string(allocatorDesc.IsUMA) + ").";
                            GPGMM_SKIP_TEST_IF(envParams.IsCapturedCapsCompat);
                        }

                        if (envParams.LogLevel <= gpgmm::LogSeverity::Warning &&
                            allocatorDesc.ResourceHeapTier != args["ResourceHeapTier"].asInt() &&
                            iterationIndex == 0) {
                            gpgmm::WarningLog()
                                << "Capture device does not match playback device "
                                   "(ResourceHeapTier: " +
                                       std::to_string(args["ResourceHeapTier"].asInt()) + " vs " +
                                       std::to_string(allocatorDesc.ResourceHeapTier) + ").";
                            GPGMM_SKIP_TEST_IF(envParams.IsCapturedCapsCompat);
                        }

                        allocatorDesc.PreferredResourceHeapSize =
                            args["PreferredResourceHeapSize"].asUInt64();
                        allocatorDesc.MaxResourceHeapSize = args["MaxResourceHeapSize"].asUInt64();
                        allocatorDesc.MaxResourceSizeForPooling =
                            args["MaxResourceSizeForPooling"].asUInt64();
                        allocatorDesc.MaxVideoMemoryBudget = args["MaxVideoMemoryBudget"].asFloat();
                        allocatorDesc.TotalResourceBudgetLimit =
                            args["TotalResourceBudgetLimit"].asUInt64();

                        ComPtr<ResourceAllocator> resourceAllocator;
                        ASSERT_SUCCEEDED(
                            ResourceAllocator::CreateAllocator(allocatorDesc, &resourceAllocator));

                        ASSERT_FALSE(allocatorInstanceID.empty());

                        ASSERT_TRUE(allocatorToIDMap
                                        .insert({allocatorInstanceID, std::move(resourceAllocator)})
                                        .second);
                    } break;

                    case TRACE_EVENT_PHASE_CREATE_OBJECT: {
                        // Assume subsequent events are always against this allocator instance.
                        // This is because call trace events have no ID associated with them.
                        allocatorInstanceID = event["id"].asString();
                    } break;

                    case TRACE_EVENT_PHASE_DELETE_OBJECT: {
                        const std::string& traceEventID = event["id"].asString();

                        auto it = allocatorToIDMap.find(traceEventID);
                        ASSERT_TRUE(it != allocatorToIDMap.end());
                        ASSERT_EQ(allocatorToIDMap.erase(traceEventID), 1u);
                    } break;

                    default:
                        break;
                }
            } else if (event["name"].asString() == "GPUMemoryBlock") {
                switch (*event["ph"].asCString()) {
                    case TRACE_EVENT_PHASE_SNAPSHOT_OBJECT: {
                        const std::string& heapID = event["id"].asString();
                        if (heapDescToIDMap.find(heapID) != heapDescToIDMap.end()) {
                            continue;
                        }

                        const Json::Value& snapshot = event["args"]["snapshot"];

                        HEAP_DESC heapDesc = {};
                        heapDesc.IsResident = snapshot["IsResident"].asBool();
                        heapDesc.MemorySegmentGroup = static_cast<DXGI_MEMORY_SEGMENT_GROUP>(
                            snapshot["MemorySegmentGroup"].asInt());
                        heapDesc.Size = snapshot["Size"].asUInt64();

                        mCapturedMemoryStats.TotalSize += heapDesc.Size;
                        mCapturedMemoryStats.TotalCount++;
                        mCapturedMemoryStats.CurrentUsage += heapDesc.Size;
                        mCapturedMemoryStats.PeakUsage = std::max(
                            mCapturedMemoryStats.PeakUsage, mCapturedMemoryStats.CurrentUsage);

                        ASSERT_TRUE(heapDescToIDMap.insert({heapID, heapDesc}).second);
                    } break;

                    case TRACE_EVENT_PHASE_DELETE_OBJECT: {
                        const std::string& traceEventID = event["id"].asString();
                        auto it = heapDescToIDMap.find(traceEventID);
                        ASSERT_TRUE(it != heapDescToIDMap.end());

                        HEAP_DESC heapDesc = it->second;
                        mCapturedMemoryStats.CurrentUsage -= heapDesc.Size;

                        ASSERT_EQ(heapDescToIDMap.erase(traceEventID), 1u);

                    } break;

                    default:
                        break;
                }
            }
        }

        ASSERT_TRUE(allocationToIDMap.empty());
        ASSERT_TRUE(allocatorToIDMap.empty());
        ASSERT_TRUE(heapDescToIDMap.empty());
    }

    CaptureReplayCallStats mReplayedAllocateStats;
    CaptureReplayCallStats mReplayedDeallocateStats;
    CaptureReplayMemoryStats mReplayedAllocationStats;

    CaptureReplayMemoryStats mCapturedAllocationStats;
    CaptureReplayMemoryStats mCapturedMemoryStats;
};

TEST_P(D3D12EventTraceReplay, AllocatorPerf) {
    RunTestLoop();

    LogCallStats("Allocation(s)", mReplayedAllocateStats);
    LogCallStats("Deallocation(s)", mReplayedDeallocateStats);

    LogMemoryStats("Allocation", mCapturedAllocationStats);
    LogMemoryStats("Memory", mCapturedMemoryStats);
}

// Verify captured does not regress (ie. consume more memory) upon playback.
TEST_P(D3D12EventTraceReplay, AllocationUsage) {
    TestEnviromentParams testEnv = {};
    testEnv.IsCapturedCapsCompat = true;
    RunTest(GetParam(), testEnv, /*iterations*/ 0);

    EXPECT_LE(mReplayedAllocationStats.TotalSize, mCapturedAllocationStats.TotalSize);
    EXPECT_LE(mReplayedAllocationStats.PeakUsage, mCapturedAllocationStats.PeakUsage);
    EXPECT_EQ(mReplayedAllocationStats.TotalCount, mCapturedAllocationStats.TotalCount);
}

// Verify a re-generated trace will always playback the same result.
TEST_P(D3D12EventTraceReplay, RegenerateSame) {
    // Regenerate capture.
    TestEnviromentParams testEnv = {};
    testEnv.IsRegenerate = true;
    RunTest(GetParam(), testEnv, /*iterations*/ 0);

    const CaptureReplayCallStats beforeReplayedAllocateStats = mReplayedAllocateStats;
    const CaptureReplayCallStats beforeReplayedDeallocateStats = mReplayedDeallocateStats;
    const CaptureReplayMemoryStats beforeCapturedAllocationStats = mCapturedAllocationStats;
    const CaptureReplayMemoryStats beforeCapturedMemoryStats = mCapturedMemoryStats;

    // Reset stats
    mReplayedAllocateStats = {};
    mReplayedDeallocateStats = {};
    mCapturedAllocationStats = {};
    mCapturedMemoryStats = {};

    // Playback re-generated capture.
    testEnv.IsRegenerate = false;
    RunTest(GetParam(), testEnv, /*iterations*/ 0);

    EXPECT_EQ(beforeReplayedAllocateStats.TotalNumOfCalls, mReplayedAllocateStats.TotalNumOfCalls);
    EXPECT_EQ(beforeReplayedDeallocateStats.TotalNumOfCalls,
              mReplayedDeallocateStats.TotalNumOfCalls);

    EXPECT_EQ(beforeCapturedAllocationStats.TotalCount, mCapturedAllocationStats.TotalCount);
    EXPECT_EQ(beforeCapturedMemoryStats.TotalCount, mCapturedMemoryStats.TotalCount);
}

GPGMM_INSTANTIATE_CAPTURE_REPLAY_TEST(D3D12EventTraceReplay);
