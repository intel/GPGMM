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
        GPGMM_SKIP_TEST_IF(!reader.parse(traceFileStream, root, false));

        ComPtr<ResourceAllocation> allocationWithoutID;
        std::unique_ptr<Heap> heapWithoutID;

        std::unordered_map<std::string, ComPtr<ResourceAllocator>> createdAllocatorToID;
        std::unordered_map<std::string, ComPtr<ResidencyManager>> createdResidencyManagerToID;
        std::unordered_map<std::string, ComPtr<ResourceAllocation>> createdAllocationToID;
        std::unordered_map<std::string, std::unique_ptr<Heap>> createdHeapToID;

        std::string currentAllocatorID;
        std::string currentResidencyID;

        std::vector<ResidencyList> currentResidencyLists;

        const Json::Value& traceEvents = root["traceEvents"];
        ASSERT_TRUE(!traceEvents.empty());

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
                        std::vector<ResidencyList*> residencyListPtrs;
                        for (auto& setJson : args["ResidencyLists"]) {
                            ResidencyList list = {};
                            for (auto heap : setJson["Heaps"]) {
                                const std::string heapId = heap["id_ref"].asString();
                                if (createdHeapToID.find(heapId) == createdHeapToID.end()) {
                                    break;
                                }
                                list.Add(createdHeapToID[heapId].get());
                            }
                            residencyListPtrs.push_back(&list);
                            currentResidencyLists.push_back(std::move(list));
                        }

                        ResidencyManager* residencyManager =
                            createdResidencyManagerToID[currentResidencyID].Get();
                        ASSERT_NE(residencyManager, nullptr);

                        ASSERT_SUCCEEDED(residencyManager->ExecuteCommandLists(
                            nullptr, nullptr, residencyListPtrs.data(),
                            static_cast<uint32_t>(residencyListPtrs.size())));

                        // Prepare for the next frame.
                        for (auto& set : currentResidencyLists) {
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

                        auto it = createdAllocatorToID.find(currentAllocatorID);
                        ASSERT_TRUE(it != createdAllocatorToID.end());

                        ResourceAllocator* resourceAllocator =
                            createdAllocatorToID[currentAllocatorID].Get();
                        ASSERT_NE(resourceAllocator, nullptr);

                        if (envParams.IsNeverAllocate) {
                            allocationDescriptor.Flags |= ALLOCATION_FLAG_NEVER_ALLOCATE_MEMORY;
                        }

                        if (envParams.IsSuballocationDisabled) {
                            allocationDescriptor.Flags |= ALLOCATION_FLAG_NEVER_SUBALLOCATE_MEMORY;
                        }

                        HRESULT hr = resourceAllocator->CreateResource(
                            allocationDescriptor, resourceDescriptor, initialResourceState,
                            clearValuePtr, &allocationWithoutID);

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
                            std::max(resourceAllocator->GetInfo().UsedMemoryUsage,
                                     mReplayedMemoryStats.PeakUsage);

                    } break;

                    default:
                        break;
                }
            } else if (event["name"].asString() == "ResourceAllocation") {
                switch (*event["ph"].asCString()) {
                    case TRACE_EVENT_PHASE_CREATE_OBJECT: {
                        if (allocationWithoutID == nullptr) {
                            continue;
                        }

                        ASSERT_TRUE(allocationWithoutID != nullptr);
                        const std::string& allocationID = event["id"].asString();
                        ASSERT_TRUE(
                            createdAllocationToID.insert({allocationID, allocationWithoutID})
                                .second);

                        ASSERT_TRUE(allocationWithoutID.Reset() == 1);
                    } break;

                    case TRACE_EVENT_PHASE_DELETE_OBJECT: {
                        const std::string& allocationID = event["id"].asString();
                        if (createdAllocationToID.find(allocationID) ==
                            createdAllocationToID.end()) {
                            continue;
                        }

                        const bool didDeallocate = createdAllocationToID.erase(allocationID);
                        ASSERT_TRUE(didDeallocate || envParams.IsNeverAllocate);

                    } break;

                    default:
                        break;
                }
            } else if (event["name"].asString() == "ResidencyManager") {
                switch (*event["ph"].asCString()) {
                    case TRACE_EVENT_PHASE_SNAPSHOT_OBJECT: {
                        const std::string& residencyManagerID = event["id"].asString();
                        if (createdResidencyManagerToID.find(residencyManagerID) !=
                            createdResidencyManagerToID.end()) {
                            continue;
                        }

                        const Json::Value& snapshot = event["args"]["snapshot"];
                        ASSERT_FALSE(snapshot.empty());

                        if (GetLogLevel() <= gpgmm::LogSeverity::Warning &&
                            mCaps->IsAdapterUMA() != snapshot["IsUMA"].asBool() &&
                            iterationIndex == 0) {
                            gpgmm::WarningLog()
                                << "Capture device does not match playback device (IsUMA: " +
                                       std::to_string(snapshot["IsUMA"].asBool()) + " vs " +
                                       std::to_string(mCaps->IsAdapterUMA()) + ").";
                            GPGMM_SKIP_TEST_IF(!envParams.IsIgnoreCapsMismatchEnabled);
                        }

                        RESIDENCY_DESC residencyDesc = {};
                        residencyDesc.Device = mDevice;
                        residencyDesc.Adapter = mAdapter;
                        residencyDesc.IsUMA = mCaps->IsAdapterUMA();
                        residencyDesc.MaxPctOfVideoMemoryToBudget =
                            snapshot["MaxPctOfVideoMemoryToBudget"].asFloat();
                        residencyDesc.MaxBudgetInBytes = snapshot["MaxBudgetInBytes"].asUInt64();
                        residencyDesc.EvictSizeInBytes = snapshot["EvictSizeInBytes"].asUInt64();
                        residencyDesc.InitialFenceValue = snapshot["InitialFenceValue"].asUInt64();

                        if (envParams.CaptureEventMask != 0) {
                            residencyDesc.RecordOptions.Flags |=
                                static_cast<EVENT_RECORD_FLAGS>(envParams.CaptureEventMask);
                            residencyDesc.RecordOptions.TraceFile = traceFile.path.c_str();
                            residencyDesc.RecordOptions.MinMessageLevel =
                                GetMessageSeverity(GetLogLevel());

                            // Keep recording across multiple playback iterations to ensure all
                            // events will be captured instead of overwritten per iteration.
                            if (envParams.Iterations == 1) {
                                residencyDesc.RecordOptions.EventScope =
                                    EVENT_RECORD_SCOPE_PER_INSTANCE;
                            }
                        }

                        residencyDesc.MinLogLevel = GetMessageSeverity(GetLogLevel());

                        ComPtr<ResidencyManager> residencyManager;
                        ASSERT_SUCCEEDED(ResidencyManager::CreateResidencyManager(
                            residencyDesc, &residencyManager));

                        ASSERT_TRUE(createdResidencyManagerToID
                                        .insert({residencyManagerID, std::move(residencyManager)})
                                        .second);
                    } break;

                    case TRACE_EVENT_PHASE_CREATE_OBJECT: {
                        // Assume subsequent events are always against this residency instance.
                        // This is because call trace events have no ID associated with them.
                        currentResidencyID = event["id"].asString();
                    } break;

                    case TRACE_EVENT_PHASE_DELETE_OBJECT: {
                        const std::string& residencyManagerID = event["id"].asString();

                        auto it = createdResidencyManagerToID.find(residencyManagerID);
                        if (it == createdResidencyManagerToID.end()) {
                            continue;
                        }

                        ASSERT_EQ(createdResidencyManagerToID.erase(residencyManagerID), 1u);
                    } break;

                    default:
                        break;
                }
            } else if (event["name"].asString() == "ResourceAllocator") {
                switch (*event["ph"].asCString()) {
                    case TRACE_EVENT_PHASE_SNAPSHOT_OBJECT: {
                        const std::string& allocatorID = event["id"].asString();
                        if (createdAllocatorToID.find(allocatorID) != createdAllocatorToID.end()) {
                            continue;
                        }

                        const Json::Value& snapshot = event["args"]["snapshot"];
                        ASSERT_FALSE(snapshot.empty());

                        ALLOCATOR_DESC allocatorDesc = CreateBasicAllocatorDesc();
                        if (!envParams.IsPrefetchAllowed) {
                            allocatorDesc.Flags |= ALLOCATOR_FLAG_DISABLE_MEMORY_PREFETCH;
                        }

                        // Apply profile (if specified).
                        if (envParams.AllocatorProfile ==
                            AllocatorProfile::ALLOCATOR_PROFILE_CAPTURED) {
                            allocatorDesc.Flags |=
                                static_cast<ALLOCATOR_FLAGS>(snapshot["Flags"].asInt());
                            allocatorDesc.PreferredResourceHeapSize =
                                snapshot["PreferredResourceHeapSize"].asUInt64();
                            allocatorDesc.MaxResourceHeapSize =
                                snapshot["MaxResourceHeapSize"].asUInt64();
                            allocatorDesc.MemoryFragmentationLimit =
                                snapshot["MemoryFragmentationLimit"].asDouble();
                            allocatorDesc.MemoryGrowthFactor =
                                snapshot["MemoryGrowthFactor"].asDouble();
                        } else if (envParams.AllocatorProfile ==
                                   AllocatorProfile::ALLOCATOR_PROFILE_MAX_PERFORMANCE) {
                            // Any amount of (internal) fragmentation is acceptable.
                            allocatorDesc.MemoryFragmentationLimit = 1.0f;
                        } else if (envParams.AllocatorProfile ==
                                   AllocatorProfile::ALLOCATOR_PROFILE_LOW_MEMORY) {
                            allocatorDesc.Flags |= ALLOCATOR_FLAG_ALWAYS_ON_DEMAND;
                            allocatorDesc.MemoryFragmentationLimit = 0.125;  // 1/8th of 4MB
                        }

                        if (envParams.CaptureEventMask != 0) {
                            allocatorDesc.RecordOptions.Flags |=
                                static_cast<EVENT_RECORD_FLAGS>(envParams.CaptureEventMask);
                            allocatorDesc.RecordOptions.TraceFile = traceFile.path.c_str();
                            allocatorDesc.RecordOptions.MinMessageLevel =
                                GetMessageSeverity(GetLogLevel());

                            // Keep recording across multiple playback iterations to ensure all
                            // events will be captured instead of overwritten per iteration.
                            if (envParams.Iterations == 1) {
                                allocatorDesc.RecordOptions.EventScope =
                                    EVENT_RECORD_SCOPE_PER_INSTANCE;
                            }
                        }

                        allocatorDesc.MinLogLevel = GetMessageSeverity(GetLogLevel());

                        if (GetLogLevel() <= gpgmm::LogSeverity::Warning &&
                            allocatorDesc.ResourceHeapTier !=
                                snapshot["ResourceHeapTier"].asInt() &&
                            iterationIndex == 0) {
                            gpgmm::WarningLog()
                                << "Capture device does not match playback device "
                                   "(ResourceHeapTier: " +
                                       std::to_string(snapshot["ResourceHeapTier"].asInt()) +
                                       " vs " + std::to_string(allocatorDesc.ResourceHeapTier) +
                                       ").";
                            GPGMM_SKIP_TEST_IF(!envParams.IsIgnoreCapsMismatchEnabled);
                        }

                        ComPtr<ResidencyManager> residencyManager;
                        if (createdResidencyManagerToID.find(currentResidencyID) !=
                            createdResidencyManagerToID.end()) {
                            residencyManager = createdResidencyManagerToID[currentResidencyID];
                        }

                        ComPtr<ResourceAllocator> resourceAllocator;
                        ASSERT_SUCCEEDED(ResourceAllocator::CreateAllocator(
                            allocatorDesc, residencyManager.Get(), &resourceAllocator));

                        ASSERT_TRUE(
                            createdAllocatorToID.insert({allocatorID, std::move(resourceAllocator)})
                                .second);
                    } break;

                    case TRACE_EVENT_PHASE_CREATE_OBJECT: {
                        // Assume subsequent events are always against this allocator instance.
                        // This is because call trace events have no ID associated with them.
                        currentAllocatorID = event["id"].asString();
                    } break;

                    case TRACE_EVENT_PHASE_DELETE_OBJECT: {
                        const std::string& allocatorID = event["id"].asString();

                        auto it = createdAllocatorToID.find(allocatorID);
                        if (it == createdAllocatorToID.end()) {
                            continue;
                        }

                        ASSERT_EQ(createdAllocatorToID.erase(allocatorID), 1u);
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

                        D3D12_HEAP_PROPERTIES heapProperties = {};
                        heapProperties.Type = static_cast<D3D12_HEAP_TYPE>(
                            args["Heap"]["Properties"]["Type"].asInt());
                        heapProperties.CPUPageProperty = static_cast<D3D12_CPU_PAGE_PROPERTY>(
                            args["Heap"]["Properties"]["CPUPageProperty"].asInt());
                        heapProperties.MemoryPoolPreference = static_cast<D3D12_MEMORY_POOL>(
                            args["Heap"]["Properties"]["MemoryPoolPreference"].asInt());

                        HEAP_DESC resourceHeapDesc = {};
                        resourceHeapDesc.SizeInBytes = args["Heap"]["SizeInBytes"].asUInt64();
                        resourceHeapDesc.Alignment = args["Heap"]["Alignment"].asUInt64();
                        resourceHeapDesc.MemorySegmentGroup = GetMemorySegmentGroup(
                            heapProperties.MemoryPoolPreference, mCaps->IsAdapterUMA());

                        ResidencyManager* residencyManager =
                            createdResidencyManagerToID[currentResidencyID].Get();
                        ASSERT_NE(residencyManager, nullptr);

                        Heap* resourceHeap = nullptr;
                        ASSERT_SUCCEEDED(Heap::CreateHeap(
                            resourceHeapDesc, residencyManager,
                            [&](ID3D12Pageable** ppPageableOut) -> HRESULT {
                                D3D12_HEAP_DESC heapDesc = {};
                                heapDesc.Properties = heapProperties;
                                heapDesc.SizeInBytes = resourceHeapDesc.SizeInBytes;
                                heapDesc.Alignment = resourceHeapDesc.Alignment;
                                heapDesc.Flags =
                                    static_cast<D3D12_HEAP_FLAGS>(args["Heap"]["Flags"].asInt());

                                ComPtr<ID3D12Heap> heap;
                                ReturnIfFailed(mDevice->CreateHeap(&heapDesc, IID_PPV_ARGS(&heap)));

                                *ppPageableOut = heap.Detach();

                                return S_OK;
                            },
                            &resourceHeap));

                        heapWithoutID.reset(resourceHeap);

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
                        if (heapWithoutID == nullptr) {
                            continue;
                        }

                        ASSERT_TRUE(heapWithoutID != nullptr);
                        const std::string& heapID = event["id"].asString();
                        ASSERT_TRUE(
                            createdHeapToID
                                .insert({heapID, std::unique_ptr<Heap>(heapWithoutID.release())})
                                .second);

                    } break;

                    case TRACE_EVENT_PHASE_DELETE_OBJECT: {
                        const std::string& heapID = event["id"].asString();
                        auto it = createdHeapToID.find(heapID);
                        if (it == createdHeapToID.end()) {
                            continue;
                        }

                        Heap* heap = it->second.get();
                        ASSERT_NE(heap, nullptr);

                        mCapturedMemoryStats.CurrentUsage -= heap->GetSize();

                        ASSERT_EQ(createdHeapToID.erase(heapID), 1u);

                    } break;

                    default:
                        break;
                }
            }
        }

        if (mReplayedMemoryStats.PeakUsage > 0) {
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
