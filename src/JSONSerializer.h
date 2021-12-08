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

#ifndef GPGMM_JSONSERIALIZER_H_
#define GPGMM_JSONSERIALIZER_H_

#include <string>

namespace gpgmm {

    // Uses the "curiously recurring template pattern" (CRTP) to allow an derived class to provide
    // overloaded methods used to serialize backend structures to disk.
    template <typename D>
    class ObjectSerializer {
      public:
        template <typename T>
        static std::string SerializeToJSON(const T& value) {
            ObjectSerializer<D> serializer;
            return static_cast<D*>(&serializer)->AppendTo(value);
        }
    };

    struct POOL_DESC;

    class JSONSerializer : public ObjectSerializer<JSONSerializer> {
      public:
        std::string AppendTo(const POOL_DESC& desc);
    };

}  // namespace gpgmm

#endif  // GPGMM_JSONSERIALIZER_H_
