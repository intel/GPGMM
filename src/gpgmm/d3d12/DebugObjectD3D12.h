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

#ifndef GPGMM_D3D12_DEBUGOBJECTD3D12_H_
#define GPGMM_D3D12_DEBUGOBJECTD3D12_H_

#include "gpgmm/d3d12/d3d12_platform.h"
#include "include/gpgmm_export.h"

#include <string>

namespace gpgmm { namespace d3d12 {

    /** \brief Debug object associates additional information for D3D objects using SetPrivateData.

    Since a single D3D object could be re-used by one or more GPGMM objects, debug information must
    be stored and retireved seperately.
    */
    class GPGMM_EXPORT DebugObject {
      public:
        DebugObject() = default;
        virtual ~DebugObject() = default;

        DebugObject(const DebugObject&) = default;
        DebugObject& operator=(const DebugObject&) = default;

        /** \brief Get the debug name.

        \return A string that contains the debug name associated with the debug object.
        */
        std::string GetDebugName() const;

        /** \brief Associate a debug name.

        @param name A string that contains the debug name to associate with the debug object.
        */
        HRESULT SetDebugName(const std::string& name);

      protected:
        // Derived classes should override to associate the name with the containing ID3D12Object.
        virtual HRESULT SetDebugNameImpl(const std::string& name) = 0;

      private:
        std::string mDebugName;
    };

}}  // namespace gpgmm::d3d12

#endif  // GPGMM_D3D12_DEBUGOBJECTD3D12_H_
