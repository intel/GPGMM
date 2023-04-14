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

#ifndef GPGMM_COMMON_OBJECT_H_
#define GPGMM_COMMON_OBJECT_H_

namespace gpgmm {

    class ObjectBase {
      public:
        ObjectBase() = default;
        virtual ~ObjectBase() = default;

        ObjectBase(const ObjectBase&) = default;
        ObjectBase& operator=(const ObjectBase&) = default;

        virtual const char* GetTypename() const = 0;
    };

// Helper to provide ObjectBase-based object types the type name based on class name.
#define DEFINE_OBJECT_BASE_OVERRIDES(type)            \
    inline const char* GetTypename() const override { \
        return #type;                                 \
    }
}  // namespace gpgmm

#endif  // GPGMM_COMMON_OBJECT_H_
