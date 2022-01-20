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

#ifndef GPGMM_GRAPHNODE_H_
#define GPGMM_GRAPHNODE_H_

#include "gpgmm/common/LinkedList.h"

#include <memory>

namespace gpgmm {

    // Exposes as a node in a DAG.
    template <typename T>
    class GraphNode : public LinkNode<T> {
      public:
        virtual ~GraphNode();

        bool HasChild() const;
        T* GetFirstChild() const;
        T* AppendChild(std::unique_ptr<T> obj);

      protected:
        LinkedList<T> mChildren;
    };

}  // namespace gpgmm

#endif  // GPGMM_GRAPHNODE_H_
