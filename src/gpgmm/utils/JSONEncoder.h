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

#ifndef GPGMM_UTILS_JSON_ENCODER_H_
#define GPGMM_UTILS_JSON_ENCODER_H_

#include <sstream>
#include <string>

namespace gpgmm {

    class JSONArray;

    class JSONDict {
      public:
        JSONDict();
        JSONDict(const std::string& name, const JSONDict& object);
        JSONDict(const JSONDict& other);
        JSONDict& operator=(const JSONDict& other);

        std::string ToString() const;
        bool IsEmpty() const;

        // Per JSON data type
        void AddItem(const std::string& name, std::string value);
        void AddItem(const std::string& name, char value);
        void AddItem(const std::string& name, const char* value);
        void AddItem(const std::string& name, uint64_t value);
        void AddItem(const std::string& name, uint32_t value);
        void AddItem(const std::string& name, bool value);
        void AddItem(const std::string& name, float value);
        void AddItem(const std::string& name, double value);
        void AddItem(const std::string& name, int value);
        void AddItem(const std::string& name, unsigned char value);
        void AddItem(const std::string& name, const JSONDict& object);
        void AddItem(const std::string& name, const JSONArray& object);

      private:
        void AddItemInternal(const std::string& name, const std::string& value);

        bool mHasItem = false;
        std::stringstream mSS;
    };

    class JSONArray {
      public:
        JSONArray();
        JSONArray(const JSONArray& other);

        std::string ToString() const;
        bool IsEmpty() const;

        // Per JSON data type
        void AddItem(const std::string& value);
        void AddItem(uint64_t value);
        void AddItem(uint32_t value);
        void AddItem(bool value);
        void AddItem(float value);
        void AddItem(double value);
        void AddItem(int value);
        void AddItem(unsigned char value);
        void AddItem(const JSONDict& object);

      private:
        void AddItemInternal(const std::string& value);

        bool mHasItem = false;
        std::stringstream mSS;
    };

}  // namespace gpgmm

#endif  // GPGMM_UTILS_JSON_ENCODER_H_
