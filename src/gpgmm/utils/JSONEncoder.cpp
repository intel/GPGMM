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

#include "JSONEncoder.h"

namespace gpgmm {

    // JSONDict

    JSONDict::JSONDict() {
        mSS << "{ ";
    }

    JSONDict::JSONDict(const std::string& name, const JSONDict& object) {
        mSS << "{ ";
        AddItem(name, object);
    }

    JSONDict::JSONDict(const JSONDict& other) {
        mSS = std::stringstream(other.mSS.str());
        mHasItem = other.mHasItem;
    }

    JSONDict& JSONDict::operator=(const JSONDict& other) {
        mSS = std::stringstream(other.mSS.str());
        mHasItem = other.mHasItem;
        return *this;
    }

    std::string JSONDict::ToString() const {
        return mSS.str() + " }";
    }

    bool JSONDict::IsEmpty() const {
        return !mHasItem;
    }

    void JSONDict::AddItem(const std::string& name, std::string value) {
        return AddItemInternal(name, "\"" + value + "\"");
    }

    void JSONDict::AddItem(const std::string& name, char value) {
        return AddItemInternal(name, "\"" + std::string(1, value) + "\"");
    }

    void JSONDict::AddItem(const std::string& name, const char* value) {
        return AddItemInternal(name, "\"" + std::string(value) + "\"");
    }

    void JSONDict::AddItem(const std::string& name, uint64_t value) {
        return AddItemInternal(name, std::to_string(value));
    }

    void JSONDict::AddItem(const std::string& name, uint32_t value) {
        return AddItemInternal(name, std::to_string(value));
    }

    void JSONDict::AddItem(const std::string& name, bool value) {
        return AddItemInternal(name, std::to_string(value));
    }

    void JSONDict::AddItem(const std::string& name, float value) {
        return AddItemInternal(name, std::to_string(value));
    }

    void JSONDict::AddItem(const std::string& name, double value) {
        return AddItemInternal(name, std::to_string(value));
    }

    void JSONDict::AddItem(const std::string& name, int value) {
        return AddItemInternal(name, std::to_string(value));
    }

    void JSONDict::AddItem(const std::string& name, unsigned char value) {
        return AddItem(name, static_cast<uint32_t>(value));
    }

    void JSONDict::AddItem(const std::string& name, const JSONDict& object) {
        return AddItemInternal(name, object.ToString());
    }

    void JSONDict::AddItem(const std::string& name, const JSONArray& object) {
        return AddItemInternal(name, object.ToString());
    }

    void JSONDict::AddItemInternal(const std::string& name, const std::string& value) {
        if (mHasItem) {
            mSS << ", ";
        }
        mSS << "\"" + name + "\": " << value;
        mHasItem = true;
    }

    // JSONArray

    JSONArray::JSONArray() {
        mSS << "[ ";
    }

    JSONArray::JSONArray(const JSONArray& other) {
        mSS = std::stringstream(other.mSS.str());
        mHasItem = other.mHasItem;
    }

    bool JSONArray::IsEmpty() const {
        return !mHasItem;
    }

    std::string JSONArray::ToString() const {
        return mSS.str() + " ]";
    }

    void JSONArray::AddItem(const std::string& value) {
        return AddItemInternal("\"" + value + "\"");
    }

    void JSONArray::AddItem(uint64_t value) {
        return AddItemInternal(std::to_string(value));
    }

    void JSONArray::AddItem(uint32_t value) {
        return AddItemInternal(std::to_string(value));
    }

    void JSONArray::AddItem(bool value) {
        return AddItemInternal(std::to_string(value));
    }

    void JSONArray::AddItem(float value) {
        return AddItemInternal(std::to_string(value));
    }

    void JSONArray::AddItem(double value) {
        return AddItemInternal(std::to_string(value));
    }

    void JSONArray::AddItem(int value) {
        return AddItemInternal(std::to_string(value));
    }

    void JSONArray::AddItem(unsigned char value) {
        return AddItem(static_cast<uint32_t>(value));
    }

    void JSONArray::AddItem(const JSONDict& object) {
        return AddItemInternal(object.ToString());
    }

    void JSONArray::AddItemInternal(const std::string& value) {
        if (mHasItem) {
            mSS << ", ";
        }
        mSS << value;
        mHasItem = true;
    }

}  // namespace gpgmm
