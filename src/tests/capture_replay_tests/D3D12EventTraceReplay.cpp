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

#include "src/tests/capture_replay_tests/GPGMMCaptureReplayTests.h"

#include "src/TraceEvent.h"
#include "src/common/Log.h"
#include "src/common/PlatformTime.h"
#include "src/d3d12/UtilsD3D12.h"
#include "src/tests/D3D12Test.h"

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
            clearValue.DepthStencil.Stencil = *depthStencilValue["Stencil"].asCString();
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

    void RunTest(const TraceFile& traceFile, const TestEnviromentParams& envParams) override {
        std::ifstream traceFileStream(traceFile.path, std::ifstream::binary);

        Json::Value root;
        Json::Reader reader;
        ASSERT_TRUE(reader.parse(traceFileStream, root, false));

        std::unordered_map<std::string, ComPtr<ResourceAllocation>> allocationToIDMap;
        std::unordered_map<std::string, ComPtr<ResourceAllocator>> allocatorToIDMap;
        std::unordered_map<std::string, HEAP_DESC> heapDescToIDMap;

        ComPtr<ResourceAllocation> newAllocationWithoutID;

        std::string allocatorInstanceID;
        ALLOCATOR_DESC allocatorDesc = {};

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

                        const ALLOCATION_DESC allocationDescriptor =
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

                        ASSERT_FALSE(allocatorInstanceID.empty());

                        mPlatformTime->StartElapsedTime();

                        ASSERT_SUCCEEDED(allocatorToIDMap[allocatorInstanceID]->CreateResource(
                            allocationDescriptor, resourceDescriptor, initialResourceState,
                            clearValuePtr, &newAllocationWithoutID));

                        mCreateResourceStats.TotalCpuTime += mPlatformTime->EndElapsedTime();
                        mCreateResourceStats.TotalNumOfCalls++;

                    } break;

                    default:
                        break;
                }
            } else if (event["name"].asString() == "ResourceAllocation") {
                switch (*event["ph"].asCString()) {
                    case TRACE_EVENT_PHASE_CREATE_OBJECT: {
                        ASSERT_TRUE(newAllocationWithoutID != nullptr);
                        const std::string& traceEventID = event["id"].asString();
                        ASSERT_TRUE(allocationToIDMap.insert({traceEventID, newAllocationWithoutID})
                                        .second);

                        mResourceAllocationStats.TotalSize += newAllocationWithoutID->GetSize();
                        mResourceAllocationStats.TotalCount++;

                        ASSERT_TRUE(newAllocationWithoutID.Reset() == 1);
                    } break;

                    case TRACE_EVENT_PHASE_DELETE_OBJECT: {
                        const std::string& traceEventID = event["id"].asString();

                        mPlatformTime->StartElapsedTime();

                        ASSERT_EQ(allocationToIDMap.erase(traceEventID), 1u);

                        mReleaseResourceStats.TotalCpuTime += mPlatformTime->EndElapsedTime();
                        mReleaseResourceStats.TotalNumOfCalls++;

                    } break;

                    default:
                        break;
                }
            } else if (event["name"].asString() == "ResourceAllocator") {
                switch (*event["ph"].asCString()) {
                    case TRACE_EVENT_PHASE_INSTANT: {
                        allocatorDesc = CreateBasicAllocatorDesc();

                        const Json::Value& args = event["args"];
                        ASSERT_FALSE(args.empty());

                        allocatorDesc.Flags = static_cast<ALLOCATOR_FLAGS>(args["Flags"].asInt());
                        if (envParams.IsStandaloneOnly) {
                            allocatorDesc.Flags = static_cast<ALLOCATOR_FLAGS>(
                                allocatorDesc.Flags | ALLOCATOR_FLAG_ALWAYS_COMMITED);
                        }

                        const Json::Value& recordOptions = args["RecordOptions"];
                        ASSERT_FALSE(recordOptions.empty());

                        if (envParams.IsRegenerate) {
                            allocatorDesc.RecordOptions.Flags = ALLOCATOR_RECORD_FLAG_TRACE_EVENTS;
                            allocatorDesc.RecordOptions.TraceFile =
                                std::string(traceFile.name + ".json");
                            allocatorDesc.RecordOptions.MinLogLevel =
                                static_cast<ALLOCATOR_MESSAGE_SEVERITY>(envParams.RecordLevel);
                        }

                        allocatorDesc.MinLogLevel =
                            static_cast<ALLOCATOR_MESSAGE_SEVERITY>(envParams.LogLevel);

                        // TODO: handle capture/re-play device mismatches.
                        if (allocatorDesc.IsUMA != args["IsUMA"].asBool()) {
                            gpgmm::WarningLog()
                                << "Capture device does not match replay device (IsUMA).";
                        }

                        if (allocatorDesc.ResourceHeapTier != args["ResourceHeapTier"].asInt()) {
                            gpgmm::WarningLog() << "Capture device does not match replay device "
                                                   "(ResourceHeapTier).";
                        }

                        allocatorDesc.PreferredResourceHeapSize =
                            args["PreferredResourceHeapSize"].asUInt64();
                        allocatorDesc.MaxResourceHeapSize = args["MaxResourceHeapSize"].asUInt64();
                        allocatorDesc.MaxResourceSizeForPooling =
                            args["MaxResourceSizeForPooling"].asUInt64();
                        allocatorDesc.MaxVideoMemoryBudget = args["MaxVideoMemoryBudget"].asFloat();
                        allocatorDesc.TotalResourceBudgetLimit =
                            args["TotalResourceBudgetLimit"].asUInt64();

                    } break;

                    case TRACE_EVENT_PHASE_CREATE_OBJECT: {
                        ComPtr<ResourceAllocator> resourceAllocator;
                        ResourceAllocator::CreateAllocator(allocatorDesc, &resourceAllocator);
                        ASSERT_NE(resourceAllocator, nullptr);

                        // Assume subsequent events are always against this allocator instance.
                        // This is because call trace events have no ID associated with them.
                        allocatorInstanceID = event["id"].asString();

                        ASSERT_TRUE(allocatorToIDMap
                                        .insert({allocatorInstanceID, std::move(resourceAllocator)})
                                        .second);
                    } break;

                    case TRACE_EVENT_PHASE_DELETE_OBJECT: {
                        const std::string& traceEventID = event["id"].asString();

                        auto it = allocatorToIDMap.find(traceEventID);
                        ASSERT_TRUE(it != allocatorToIDMap.end());

                        QUERY_RESOURCE_ALLOCATOR_INFO info = {};
                        ComPtr<ResourceAllocator> allocator = it->second;
                        ASSERT_SUCCEEDED(allocator->QueryResourceAllocatorInfo(&info));

                        mHeapStats.TotalCount = info.UsedResourceHeapCount;
                        mHeapStats.TotalSize = info.UsedResourceHeapUsage;

                        ASSERT_EQ(allocatorToIDMap.erase(traceEventID), 1u);
                    } break;

                    default:
                        break;
                }
            } else if (event["name"].asString() == "Heap") {
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

                        mHeapStats.CurrentUsage += heapDesc.Size;
                        mHeapStats.PeakUsage =
                            std::max(mHeapStats.PeakUsage, mHeapStats.CurrentUsage);

                        ASSERT_TRUE(heapDescToIDMap.insert({heapID, heapDesc}).second);
                    } break;

                    case TRACE_EVENT_PHASE_DELETE_OBJECT: {
                        const std::string& traceEventID = event["id"].asString();
                        auto it = heapDescToIDMap.find(traceEventID);
                        ASSERT_TRUE(it != heapDescToIDMap.end());

                        HEAP_DESC heapDesc = it->second;
                        mHeapStats.CurrentUsage -= heapDesc.Size;

                        ASSERT_EQ(heapDescToIDMap.erase(traceEventID), 1u);

                    } break;

                    default:
                        break;
                }
            }
        }

        ASSERT_TRUE(allocationToIDMap.empty());
        ASSERT_TRUE(allocatorToIDMap.empty());
    }

    CaptureReplayCallStats mCreateResourceStats;
    CaptureReplayCallStats mReleaseResourceStats;

    CaptureReplayMemoryStats mResourceAllocationStats;
    CaptureReplayMemoryStats mHeapStats;
};

TEST_P(D3D12EventTraceReplay, Run) {
    RunTestLoop();

    LogCallStats("CreateResource", mCreateResourceStats);
    LogCallStats("ReleaseResource", mReleaseResourceStats);
    LogMemoryStats("ResourceAllocation", mResourceAllocationStats);
    LogMemoryStats("Heap", mHeapStats);
}

GPGMM_INSTANTIATE_CAPTURE_REPLAY_TEST(D3D12EventTraceReplay);
