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

#include "gpgmm/Serializer.h"

#include "gpgmm/Allocator.h"
#include "gpgmm/MemoryAllocator.h"
#include "gpgmm/MemoryPool.h"

#include <sstream>

namespace gpgmm {

    // Messages with equal or greater to severity will be logged.
    LogSeverity gRecordEventLevel = LogSeverity::Info;

    LogSeverity SetRecordEventLevel(const LogSeverity& newLevel) {
        LogSeverity oldLevel = gRecordEventLevel;
        gRecordEventLevel = newLevel;
        return oldLevel;
    }

    const LogSeverity& GetRecordEventLevel() {
        return gRecordEventLevel;
    }

    // JSONDict

    JSONDict::JSONDict() {
        mSS << "{ ";
    }

    std::string JSONDict::ToString() const {
        return mSS.str() + " }";
    }

    void JSONDict::AddItem(const std::string& name, std::string value) {
        return AddString(name, "\"" + value + "\"");
    }

    void JSONDict::AddItem(const std::string& name, uint64_t value) {
        return AddString(name, std::to_string(value));
    }

    void JSONDict::AddItem(const std::string& name, uint32_t value) {
        return AddString(name, std::to_string(value));
    }

    void JSONDict::AddItem(const std::string& name, bool value) {
        return AddString(name, std::to_string(value));
    }

    void JSONDict::AddItem(const std::string& name, float value) {
        return AddString(name, std::to_string(value));
    }

    void JSONDict::AddItem(const std::string& name, double value) {
        return AddString(name, std::to_string(value));
    }

    void JSONDict::AddItem(const std::string& name, int value) {
        return AddString(name, std::to_string(value));
    }

    void JSONDict::AddItem(const std::string& name, unsigned char value) {
        return AddItem(name, static_cast<uint32_t>(value));
    }

    void JSONDict::AddItem(const std::string& name, const JSONDict& object) {
        return AddString(name, object.ToString());
    }

    void JSONDict::AddString(const std::string& name, const std::string& value) {
        if (mHasItem) {
            mSS << ", ";
        }
        mSS << "\"" + name + "\": " << value;
        mHasItem = true;
    }

    // Serializer

    // static
    JSONDict Serializer::Serialize(const POOL_INFO& info) {
        JSONDict dict;
        dict.AddItem("PoolSizeInBytes", info.PoolSizeInBytes);
        return dict;
    }

    // static
    JSONDict Serializer::Serialize(const ALLOCATOR_MESSAGE& desc) {
        JSONDict dict;
        dict.AddItem("Description", desc.Description);
        dict.AddItem("ID", desc.ID);
        return dict;
    }

    // static
    JSONDict Serializer::Serialize(const MEMORY_ALLOCATOR_INFO& info) {
        JSONDict dict;
        dict.AddItem("UsedBlockCount", info.UsedBlockCount);
        dict.AddItem("UsedMemoryCount", info.UsedMemoryCount);
        dict.AddItem("UsedBlockUsage", info.UsedBlockUsage);
        dict.AddItem("FreeMemoryUsage", info.FreeMemoryUsage);
        dict.AddItem("UsedMemoryUsage", info.UsedMemoryUsage);
        return dict;
    }

    // static
    JSONDict Serializer::Serialize(void* objectPtr) {
        std::stringstream objectRef;
        objectRef << std::hex << TraceEventID(objectPtr).GetID();

        JSONDict dict;
        dict.AddItem(TraceEventID::kIdRefKey, "0x" + objectRef.str());
        return dict;
    }

}  // namespace gpgmm
