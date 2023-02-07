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

#include "gpgmm/common/JSONSerializer.h"

#include "gpgmm/common/EventMessage.h"
#include "gpgmm/common/MemoryAllocator.h"
#include "gpgmm/common/MemoryPool.h"
#include "gpgmm/utils/Utils.h"

namespace gpgmm {

    // static
    JSONDict JSONSerializer::Serialize() {
        return {};
    }

    // static
    JSONDict JSONSerializer::Serialize(const MessageInfo& info) {
        JSONDict dict;
        dict.AddItem("Description", info.Description);
        dict.AddItem("ID", static_cast<uint32_t>(info.ID));
        return dict;
    }

    // static
    JSONDict JSONSerializer::Serialize(const MemoryAllocatorStats& info) {
        JSONDict dict;
        dict.AddItem("UsedBlockCount", info.UsedBlockCount);
        dict.AddItem("UsedMemoryCount", info.UsedMemoryCount);
        dict.AddItem("UsedBlockUsage", info.UsedBlockUsage);
        dict.AddItem("FreeMemoryUsage", info.FreeMemoryUsage);
        dict.AddItem("UsedMemoryUsage", info.UsedMemoryUsage);
        return dict;
    }

    // static
    JSONDict JSONSerializer::Serialize(const MemoryAllocationRequest& desc) {
        JSONDict dict;
        dict.AddItem("SizeInBytes", desc.SizeInBytes);
        dict.AddItem("Alignment", desc.Alignment);
        dict.AddItem("NeverAllocate", desc.NeverAllocate);
        dict.AddItem("AlwaysCacheSize", desc.AlwaysCacheSize);
        dict.AddItem("AlwaysPrefetch", desc.AlwaysPrefetch);
        dict.AddItem("AvailableForAllocation", desc.AvailableForAllocation);
        return dict;
    }

    // static
    JSONDict JSONSerializer::Serialize(const void* objectPtr) {
        JSONDict dict;
        dict.AddItem(TraceEventID::kIdRefKey, ToString(objectPtr));
        return dict;
    }

}  // namespace gpgmm
