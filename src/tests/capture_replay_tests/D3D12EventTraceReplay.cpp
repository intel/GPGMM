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
//

#include "tests/capture_replay_tests/GPGMMCaptureReplayTests.h"

#include "gpgmm/common/SizeClass.h"
#include "gpgmm/common/TraceEventPhase.h"
#include "gpgmm/d3d12/CapsD3D12.h"
#include "gpgmm/d3d12/ErrorD3D12.h"
#include "gpgmm/d3d12/ResourceHeapAllocatorD3D12.h"
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

    ALLOCATION_DESC ConvertToAllocationDesc(const Json::Value& allocationDescJson) {
        ALLOCATION_DESC allocationDesc = {};
        allocationDesc.Flags = static_cast<ALLOCATION_FLAGS>(allocationDescJson["Flags"].asInt());
        allocationDesc.HeapType =
            static_cast<D3D12_HEAP_TYPE>(allocationDescJson["HeapType"].asInt());
        allocationDesc.ExtraRequiredHeapFlags =
            static_cast<D3D12_HEAP_FLAGS>(allocationDescJson["ExtraRequiredHeapFlags"].asInt());
        allocationDesc.RequireResourceHeapPadding =
            allocationDescJson["RequireResourceHeapPadding"].asUInt64();
        return allocationDesc;
    }

    D3D12_CLEAR_VALUE ConvertToD3D12ClearValue(const Json::Value& clearValueJson) {
        D3D12_CLEAR_VALUE clearValue = {};
        clearValue.Format = static_cast<DXGI_FORMAT>(clearValueJson["Format"].asInt());
        if (IsDepthFormat(clearValue.Format)) {
            const Json::Value& depthStencilValue = clearValueJson["DepthStencil"];
            clearValue.DepthStencil.Depth = depthStencilValue["Depth"].asFloat();
            clearValue.DepthStencil.Stencil = depthStencilValue["Stencil"].asUInt();
        } else {
            const Json::Value& rgba = clearValueJson["Color"];
            clearValue.Color[0] = rgba["R"].asFloat();
            clearValue.Color[1] = rgba["G"].asFloat();
            clearValue.Color[2] = rgba["B"].asFloat();
            clearValue.Color[3] = rgba["A"].asFloat();
        }
        return clearValue;
    }

    D3D12_RESOURCE_DESC ConvertToD3D12ResourceDesc(const Json::Value& resourceDescJson) {
        D3D12_RESOURCE_DESC resourceDesc = {};
        resourceDesc.Dimension =
            static_cast<D3D12_RESOURCE_DIMENSION>(resourceDescJson["Dimension"].asInt());
        resourceDesc.Alignment = resourceDescJson["Alignment"].asUInt64();
        resourceDesc.Width = resourceDescJson["Width"].asUInt64();
        resourceDesc.Height = resourceDescJson["Height"].asUInt();
        resourceDesc.DepthOrArraySize = resourceDescJson["DepthOrArraySize"].asUInt();
        resourceDesc.MipLevels = resourceDescJson["MipLevels"].asUInt();

        const Json::Value& sampleDescJson = resourceDescJson["SampleDesc"];
        resourceDesc.SampleDesc.Count = sampleDescJson["Count"].asUInt();
        resourceDesc.SampleDesc.Quality = sampleDescJson["Quality"].asUInt();

        resourceDesc.Format = static_cast<DXGI_FORMAT>(resourceDescJson["Format"].asInt());
        resourceDesc.Layout = static_cast<D3D12_TEXTURE_LAYOUT>(resourceDescJson["Layout"].asInt());
        resourceDesc.Flags = static_cast<D3D12_RESOURCE_FLAGS>(resourceDescJson["Flags"].asInt());

        return resourceDesc;
    }

    ALLOCATOR_DESC ConvertAndApplyToAllocatorDesc(const Json::Value& allocatorDescJson,
                                                  const ALLOCATOR_DESC& allocatorDesc) {
        ALLOCATOR_DESC newAllocatorDesc = allocatorDesc;
        newAllocatorDesc.Flags |= static_cast<ALLOCATOR_FLAGS>(allocatorDescJson["Flags"].asInt());
        newAllocatorDesc.ResourceHeapTier =
            static_cast<D3D12_RESOURCE_HEAP_TIER>(allocatorDescJson["ResourceHeapTier"].asInt());
        newAllocatorDesc.SubAllocationAlgorithm =
            static_cast<ALLOCATOR_ALGORITHM>(allocatorDescJson["SubAllocationAlgorithm"].asInt());
        newAllocatorDesc.PoolAlgorithm =
            static_cast<ALLOCATOR_ALGORITHM>(allocatorDescJson["PoolAlgorithm"].asInt());
        newAllocatorDesc.PreferredResourceHeapSize =
            allocatorDescJson["PreferredResourceHeapSize"].asUInt64();
        newAllocatorDesc.MaxResourceHeapSize = allocatorDescJson["MaxResourceHeapSize"].asUInt64();
        newAllocatorDesc.MemoryFragmentationLimit =
            allocatorDescJson["MemoryFragmentationLimit"].asDouble();
        newAllocatorDesc.MemoryGrowthFactor = allocatorDescJson["MemoryGrowthFactor"].asDouble();
        return newAllocatorDesc;
    }

    RESIDENCY_DESC ConvertAndApplyToResidencyDesc(const Json::Value& residencyDescJson,
                                                  const RESIDENCY_DESC& residencyDesc) {
        RESIDENCY_DESC newResidencyDesc = residencyDesc;
        newResidencyDesc.Flags |= static_cast<RESIDENCY_FLAGS>(residencyDescJson["Flags"].asInt());
        newResidencyDesc.MaxPctOfVideoMemoryToBudget =
            residencyDescJson["MaxPctOfVideoMemoryToBudget"].asFloat();
        newResidencyDesc.MinPctOfBudgetToReserve =
            residencyDescJson["MinPctOfBudgetToReserve"].asFloat();
        newResidencyDesc.MaxBudgetInBytes = residencyDescJson["MaxBudgetInBytes"].asUInt64();
        newResidencyDesc.EvictSizeInBytes = residencyDescJson["EvictSizeInBytes"].asUInt64();
        newResidencyDesc.InitialFenceValue = residencyDescJson["InitialFenceValue"].asUInt64();
        return newResidencyDesc;
    }

    D3D12_HEAP_PROPERTIES ConvertToD3D12HeapProperties(const Json::Value& heapPropertiesJson) {
        D3D12_HEAP_PROPERTIES heapProperties = {};
        heapProperties.Type = static_cast<D3D12_HEAP_TYPE>(heapPropertiesJson["Type"].asInt());
        heapProperties.CPUPageProperty =
            static_cast<D3D12_CPU_PAGE_PROPERTY>(heapPropertiesJson["CPUPageProperty"].asInt());
        heapProperties.MemoryPoolPreference =
            static_cast<D3D12_MEMORY_POOL>(heapPropertiesJson["MemoryPoolPreference"].asInt());
        return heapProperties;
    }

    HEAP_DESC ConvertAndApplyToHeapDesc(const Json::Value& heapJson, const HEAP_DESC& heapDesc) {
        HEAP_DESC newHeapDesc = heapDesc;
        newHeapDesc.SizeInBytes = heapJson["SizeInBytes"].asUInt64();
        newHeapDesc.Alignment = heapJson["Alignment"].asUInt64();
        newHeapDesc.Flags = static_cast<HEAP_FLAGS>(heapJson["Flags"].asInt());
        return newHeapDesc;
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

    struct PlaybackExecutionContext {
        using InstanceID = std::string;

        ComPtr<IResourceAllocation> CurrentAllocationWithoutID;
        ComPtr<IHeap> CurrentHeapWithoutID;

        std::unordered_map<InstanceID, ComPtr<IResourceAllocator>> CreatedAllocatorsToID;
        std::unordered_map<InstanceID, ComPtr<IResidencyManager>> CreatedResidencyManagersToID;
        std::unordered_map<InstanceID, ComPtr<IResourceAllocation>> CreatedAllocationsToID;
        std::unordered_map<InstanceID, ComPtr<IHeap>> CreatedHeapsToID;

        InstanceID currentAllocatorID;
        InstanceID currentResidencyID;

        std::vector<ComPtr<IResidencyList>> currentResidencyLists;
    };

    void RunTest(const TraceFile& traceFile,
                 const TestEnviromentParams& envParams,
                 const uint64_t iterationIndex) override {
        std::ifstream traceFileStream(traceFile.path, std::ifstream::binary);

        Json::Value root;
        Json::Reader reader;
        GPGMM_SKIP_TEST_IF(!reader.parse(traceFileStream, root, false));

        PlaybackExecutionContext playbackContext = {};

        const Json::Value& traceEvents = root["traceEvents"];
        ASSERT_TRUE(!traceEvents.empty());

        ALLOCATOR_DESC baseAllocatorDesc = CreateBasicAllocatorDesc();

        // Captures never store recording options, they must be always specified.
        baseAllocatorDesc.RecordOptions.Flags |=
            static_cast<gpgmm::EventRecordFlags>(envParams.CaptureEventMask);
        baseAllocatorDesc.RecordOptions.TraceFile = traceFile.path.c_str();
        baseAllocatorDesc.MinRecordLevel = baseAllocatorDesc.MinLogLevel;

        // Keep recording across multiple playback iterations to ensure all
        // events will be captured instead of overwritten per iteration.
        if (envParams.Iterations == 1) {
            baseAllocatorDesc.RecordOptions.EventScope = gpgmm::EventRecordScope::kPerInstance;
        }

        if (!envParams.IsPrefetchAllowed) {
            baseAllocatorDesc.Flags |= ALLOCATOR_FLAG_DISABLE_MEMORY_PREFETCH;
        }

        RESIDENCY_DESC baseResidencyDesc = CreateBasicResidencyDesc();
        baseResidencyDesc.RecordOptions = baseAllocatorDesc.RecordOptions;

        for (Json::Value::ArrayIndex eventIndex = 0; eventIndex < traceEvents.size();
             eventIndex++) {
            const Json::Value& event = traceEvents[eventIndex];

            if (event["name"].asString() == "ResidencyManager.ExecuteCommandLists") {
                switch (*event["ph"].asCString()) {
                    case TRACE_EVENT_PHASE_INSTANT: {
                        const Json::Value& args = event["args"];
                        ASSERT_FALSE(args.empty());

                        // TODO: Consider encoding type instead of checking fields.
                        if (IsErrorEvent(args)) {
                            continue;
                        }

                        // Create ResidencyLists.
                        std::vector<IResidencyList*> residencyListPtrs;
                        for (auto& setJson : args["ResidencyLists"]) {
                            ComPtr<IResidencyList> list;
                            ASSERT_SUCCEEDED(CreateResidencyList(&list));
                            for (auto heap : setJson["Heaps"]) {
                                const std::string heapId = heap["id_ref"].asString();
                                if (playbackContext.CreatedHeapsToID.find(heapId) ==
                                    playbackContext.CreatedHeapsToID.end()) {
                                    break;
                                }
                                list->Add(playbackContext.CreatedHeapsToID[heapId].Get());
                            }
                            residencyListPtrs.push_back(list.Get());
                            playbackContext.currentResidencyLists.push_back(std::move(list));
                        }

                        IResidencyManager* residencyManager =
                            playbackContext
                                .CreatedResidencyManagersToID[playbackContext.currentResidencyID]
                                .Get();
                        ASSERT_NE(residencyManager, nullptr);

                        ASSERT_SUCCEEDED(residencyManager->ExecuteCommandLists(
                            nullptr, nullptr, residencyListPtrs.data(),
                            static_cast<uint32_t>(residencyListPtrs.size())));

                        // Prepare for the next frame.
                        for (auto& set : playbackContext.currentResidencyLists) {
                            set.Reset();
                        }

                    } break;

                    default:
                        break;
                }
            }

            if (event["name"].asString() == "ResourceAllocator.CreateResource") {
                switch (*event["ph"].asCString()) {
                    case TRACE_EVENT_PHASE_INSTANT: {
                        const Json::Value& args = event["args"];
                        ASSERT_FALSE(args.empty());

                        if (envParams.IsAllocationPlaybackDisabled) {
                            continue;
                        }

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

                        auto it = playbackContext.CreatedAllocatorsToID.find(
                            playbackContext.currentAllocatorID);
                        ASSERT_TRUE(it != playbackContext.CreatedAllocatorsToID.end());

                        ComPtr<IResourceAllocator> resourceAllocator =
                            playbackContext
                                .CreatedAllocatorsToID[playbackContext.currentAllocatorID]
                                .Get();
                        ASSERT_NE(resourceAllocator, nullptr);

                        if (envParams.IsNeverAllocate) {
                            allocationDescriptor.Flags |= ALLOCATION_FLAG_NEVER_ALLOCATE_MEMORY;
                        }

                        if (envParams.IsSuballocationDisabled) {
                            allocationDescriptor.Flags |= ALLOCATION_FLAG_NEVER_SUBALLOCATE_MEMORY;
                        }

                        HRESULT hr = resourceAllocator->CreateResource(
                            allocationDescriptor, resourceDescriptor, initialResourceState,
                            clearValuePtr, &playbackContext.CurrentAllocationWithoutID);

                        if (FAILED(hr)) {
                            if (envParams.IsNeverAllocate) {
                                continue;
                            } else {
                                gpgmm::ErrorLog()
                                    << "CreateResource failed with :" << args << ".\n";
                                ASSERT_SUCCEEDED(hr);
                            }
                        }

                        mReplayedMemoryStats.PeakUsage =
                            std::max(GetStats(resourceAllocator).UsedMemoryUsage,
                                     mReplayedMemoryStats.PeakUsage);

                    } break;

                    default:
                        break;
                }
            } else if (event["name"].asString() == "ResourceAllocation") {
                switch (*event["ph"].asCString()) {
                    case TRACE_EVENT_PHASE_CREATE_OBJECT: {
                        if (playbackContext.CurrentAllocationWithoutID == nullptr) {
                            continue;
                        }

                        ASSERT_TRUE(playbackContext.CurrentAllocationWithoutID != nullptr);
                        const std::string& allocationID = event["id"].asString();
                        ASSERT_TRUE(
                            playbackContext.CreatedAllocationsToID
                                .insert({allocationID, playbackContext.CurrentAllocationWithoutID})
                                .second);

                        ASSERT_TRUE(playbackContext.CurrentAllocationWithoutID.Reset() == 1);
                    } break;

                    case TRACE_EVENT_PHASE_DELETE_OBJECT: {
                        const std::string& allocationID = event["id"].asString();
                        if (playbackContext.CreatedAllocationsToID.find(allocationID) ==
                            playbackContext.CreatedAllocationsToID.end()) {
                            continue;
                        }

                        const bool didDeallocate =
                            playbackContext.CreatedAllocationsToID.erase(allocationID);
                        ASSERT_TRUE(didDeallocate || envParams.IsNeverAllocate);

                    } break;

                    default:
                        break;
                }
            } else if (event["name"].asString() == "ResidencyManager") {
                switch (*event["ph"].asCString()) {
                    case TRACE_EVENT_PHASE_SNAPSHOT_OBJECT: {
                        const std::string& residencyManagerID = event["id"].asString();
                        if (playbackContext.CreatedResidencyManagersToID.find(residencyManagerID) !=
                            playbackContext.CreatedResidencyManagersToID.end()) {
                            continue;
                        }

                        const Json::Value& snapshot = event["args"]["snapshot"];
                        ASSERT_FALSE(snapshot.empty());

                        if (GetLogLevel() <= gpgmm::MessageSeverity::kWarning &&
                            mCaps->IsAdapterUMA() != snapshot["IsUMA"].asBool() &&
                            iterationIndex == 0) {
                            gpgmm::WarningLog()
                                << "Capture device does not match playback device (IsUMA: " +
                                       std::to_string(snapshot["IsUMA"].asBool()) + " vs " +
                                       std::to_string(mCaps->IsAdapterUMA()) + ").";
                            GPGMM_SKIP_TEST_IF(!envParams.IsIgnoreCapsMismatchEnabled);
                        }

                        RESIDENCY_DESC newResidencyDesc = baseResidencyDesc;
                        newResidencyDesc =
                            ConvertAndApplyToResidencyDesc(snapshot, newResidencyDesc);

                        ComPtr<IResidencyManager> residencyManager;
                        ASSERT_SUCCEEDED(CreateResidencyManager(newResidencyDesc, mDevice.Get(),
                                                                mAdapter.Get(), &residencyManager));

                        ASSERT_TRUE(playbackContext.CreatedResidencyManagersToID
                                        .insert({residencyManagerID, std::move(residencyManager)})
                                        .second);
                    } break;

                    case TRACE_EVENT_PHASE_CREATE_OBJECT: {
                        // Assume subsequent events are always against this residency instance.
                        // This is because call trace events have no ID associated with them.
                        playbackContext.currentResidencyID = event["id"].asString();
                    } break;

                    case TRACE_EVENT_PHASE_DELETE_OBJECT: {
                        const std::string& residencyManagerID = event["id"].asString();

                        auto it =
                            playbackContext.CreatedResidencyManagersToID.find(residencyManagerID);
                        if (it == playbackContext.CreatedResidencyManagersToID.end()) {
                            continue;
                        }

                        ASSERT_EQ(
                            playbackContext.CreatedResidencyManagersToID.erase(residencyManagerID),
                            1u);
                    } break;

                    default:
                        break;
                }
            } else if (event["name"].asString() == "ResourceAllocator") {
                switch (*event["ph"].asCString()) {
                    case TRACE_EVENT_PHASE_SNAPSHOT_OBJECT: {
                        const std::string& allocatorID = event["id"].asString();
                        if (playbackContext.CreatedAllocatorsToID.find(allocatorID) !=
                            playbackContext.CreatedAllocatorsToID.end()) {
                            continue;
                        }

                        const Json::Value& snapshot = event["args"]["snapshot"];
                        ASSERT_FALSE(snapshot.empty());

                        if (GetLogLevel() <= gpgmm::MessageSeverity::kWarning &&
                            mCaps->GetMaxResourceHeapTierSupported() <
                                snapshot["ResourceHeapTier"].asInt() &&
                            iterationIndex == 0) {
                            gpgmm::WarningLog()
                                << "Captured device exceeds capabilities of playback device "
                                   "(ResourceHeapTier: " +
                                       std::to_string(snapshot["ResourceHeapTier"].asInt()) +
                                       " vs " +
                                       std::to_string(mCaps->GetMaxResourceHeapTierSupported()) +
                                       ").";
                            GPGMM_SKIP_TEST_IF(!envParams.IsIgnoreCapsMismatchEnabled);
                        }

                        ALLOCATOR_DESC allocatorDescOfProfile = baseAllocatorDesc;
                        // Apply profile (if specified).
                        if (envParams.AllocatorProfile ==
                            AllocatorProfile::ALLOCATOR_PROFILE_CAPTURED) {
                            allocatorDescOfProfile =
                                ConvertAndApplyToAllocatorDesc(snapshot, allocatorDescOfProfile);
                        } else if (envParams.AllocatorProfile ==
                                   AllocatorProfile::ALLOCATOR_PROFILE_MAX_PERFORMANCE) {
                            // Any amount of (internal) fragmentation is acceptable.
                            allocatorDescOfProfile.MemoryFragmentationLimit = 1.0f;
                        } else if (envParams.AllocatorProfile ==
                                   AllocatorProfile::ALLOCATOR_PROFILE_LOW_MEMORY) {
                            allocatorDescOfProfile.Flags |= ALLOCATOR_FLAG_ALWAYS_ON_DEMAND;
                            allocatorDescOfProfile.MemoryFragmentationLimit =
                                0.125;  // 1/8th of 4MB
                        }

                        ComPtr<IResidencyManager> residencyManager;
                        if (playbackContext.CreatedResidencyManagersToID.find(
                                playbackContext.currentResidencyID) !=
                            playbackContext.CreatedResidencyManagersToID.end()) {
                            residencyManager = playbackContext.CreatedResidencyManagersToID
                                                   [playbackContext.currentResidencyID];
                        }

                        ComPtr<IResourceAllocator> resourceAllocator;
                        ASSERT_SUCCEEDED(CreateResourceAllocator(
                            allocatorDescOfProfile, mDevice.Get(), mAdapter.Get(),
                            residencyManager.Get(), &resourceAllocator));

                        ASSERT_TRUE(playbackContext.CreatedAllocatorsToID
                                        .insert({allocatorID, std::move(resourceAllocator)})
                                        .second);
                    } break;

                    case TRACE_EVENT_PHASE_CREATE_OBJECT: {
                        // Assume subsequent events are always against this allocator instance.
                        // This is because call trace events have no ID associated with them.
                        playbackContext.currentAllocatorID = event["id"].asString();
                    } break;

                    case TRACE_EVENT_PHASE_DELETE_OBJECT: {
                        const std::string& allocatorID = event["id"].asString();

                        auto it = playbackContext.CreatedAllocatorsToID.find(allocatorID);
                        if (it == playbackContext.CreatedAllocatorsToID.end()) {
                            continue;
                        }

                        ASSERT_EQ(playbackContext.CreatedAllocatorsToID.erase(allocatorID), 1u);
                    } break;

                    default:
                        break;
                }
            } else if (event["name"].asString() == "Heap.CreateHeap") {
                switch (*event["ph"].asCString()) {
                    case TRACE_EVENT_PHASE_INSTANT: {
                        const Json::Value& args = event["args"];
                        ASSERT_FALSE(args.empty());

                        // Only ID3D12Resource or ID3D12Heaps can be created.
                        if (args["Heap"].empty()) {
                            continue;
                        }

                        if (envParams.IsMemoryPlaybackDisabled) {
                            continue;
                        }

                        const D3D12_HEAP_PROPERTIES heapProperties =
                            ConvertToD3D12HeapProperties(args["Heap"]["Properties"]);

                        HEAP_DESC resourceHeapDesc = {};
                        resourceHeapDesc.MemorySegmentGroup = GetMemorySegmentGroup(
                            heapProperties.MemoryPoolPreference, mCaps->IsAdapterUMA());
                        resourceHeapDesc =
                            ConvertAndApplyToHeapDesc(args["Heap"], resourceHeapDesc);

                        IResidencyManager* residencyManager =
                            playbackContext
                                .CreatedResidencyManagersToID[playbackContext.currentResidencyID]
                                .Get();
                        ASSERT_NE(residencyManager, nullptr);

                        D3D12_HEAP_FLAGS heapFlags =
                            static_cast<D3D12_HEAP_FLAGS>(args["Heap"]["Flags"].asInt());

                        D3D12_HEAP_DESC heapDesc = {};
                        heapDesc.Properties = heapProperties;
                        heapDesc.SizeInBytes = resourceHeapDesc.SizeInBytes;
                        heapDesc.Alignment = resourceHeapDesc.Alignment;
                        heapDesc.Flags = heapFlags;

                        CreateResourceHeapCallbackContext createHeapContext(mDevice.Get(),
                                                                            &heapDesc);

                        ComPtr<IHeap> resourceHeap;
                        ASSERT_SUCCEEDED(CreateHeap(resourceHeapDesc, residencyManager,
                                                    CreateResourceHeapCallbackContext::CreateHeap,
                                                    &createHeapContext, &resourceHeap));

                        playbackContext.CurrentHeapWithoutID = std::move(resourceHeap);

                        mCapturedMemoryStats.CurrentUsage += resourceHeapDesc.SizeInBytes;
                        mCapturedMemoryStats.PeakUsage = std::max(
                            mCapturedMemoryStats.PeakUsage, mCapturedMemoryStats.CurrentUsage);

                    } break;

                    default:
                        break;
                }
            } else if (event["name"].asString() == "Heap") {
                switch (*event["ph"].asCString()) {
                    case TRACE_EVENT_PHASE_CREATE_OBJECT: {
                        if (playbackContext.CurrentHeapWithoutID == nullptr) {
                            continue;
                        }

                        ASSERT_TRUE(playbackContext.CurrentHeapWithoutID != nullptr);
                        const std::string& heapID = event["id"].asString();
                        ASSERT_TRUE(
                            playbackContext.CreatedHeapsToID
                                .insert({heapID, std::move(playbackContext.CurrentHeapWithoutID)})
                                .second);

                    } break;

                    case TRACE_EVENT_PHASE_DELETE_OBJECT: {
                        const std::string& heapID = event["id"].asString();
                        auto it = playbackContext.CreatedHeapsToID.find(heapID);
                        if (it == playbackContext.CreatedHeapsToID.end()) {
                            continue;
                        }

                        IHeap* heap = it->second.Get();
                        ASSERT_NE(heap, nullptr);

                        mCapturedMemoryStats.CurrentUsage -= heap->GetInfo().SizeInBytes;

                        ASSERT_EQ(playbackContext.CreatedHeapsToID.erase(heapID), 1u);

                    } break;

                    default:
                        break;
                }
            }
        }

        if (mReplayedMemoryStats.PeakUsage > 0 && mCapturedMemoryStats.PeakUsage > 0) {
            gpgmm::InfoLog() << "GPU memory peak usage (captured vs replayed): "
                             << GPGMM_BYTES_TO_MB(mCapturedMemoryStats.PeakUsage) << " vs "
                             << GPGMM_BYTES_TO_MB(mReplayedMemoryStats.PeakUsage) << " MB";
        }
    }

    CaptureReplayMemoryStats mReplayedMemoryStats;
    CaptureReplayMemoryStats mCapturedMemoryStats;
};

// Playback the captured trace as-is.
TEST_P(D3D12EventTraceReplay, Replay) {
    TestEnviromentParams forceParams = {};

    RunSingleTest(forceParams);
}

// Verify that playback of a captured trace does not exceed peak usage.
TEST_P(D3D12EventTraceReplay, PeakUsage) {
    TestEnviromentParams forceParams = {};
    RunSingleTest(forceParams);

    EXPECT_LE(mReplayedMemoryStats.PeakUsage, mCapturedMemoryStats.PeakUsage);
}

// Verify that playback with pre-fetching enabled will succeed.
TEST_P(D3D12EventTraceReplay, AllowPrefetch) {
    TestEnviromentParams forceParams = {};
    forceParams.IsPrefetchAllowed = true;

    RunTestLoop(forceParams);
}

// Verify no heap re-use through sub-allocation will succeed.
TEST_P(D3D12EventTraceReplay, DisableSuballocation) {
    TestEnviromentParams forceParams = {};
    forceParams.IsSuballocationDisabled = true;

    RunSingleTest(forceParams);

    EXPECT_LE(mReplayedMemoryStats.PeakUsage, mCapturedMemoryStats.PeakUsage);
}

// Verify that playback no memory created will succeed.
TEST_P(D3D12EventTraceReplay, NeverAllocate) {
    TestEnviromentParams forceParams = {};
    forceParams.IsNeverAllocate = true;

    RunSingleTest(forceParams);

    EXPECT_LE(mReplayedMemoryStats.PeakUsage, 0u);
}

GPGMM_INSTANTIATE_CAPTURE_REPLAY_TEST(D3D12EventTraceReplay);
