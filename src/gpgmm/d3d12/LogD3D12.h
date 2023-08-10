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

#ifndef SRC_GPGMM_D3D12_LOGD3D12_H_
#define SRC_GPGMM_D3D12_LOGD3D12_H_

#include "gpgmm/utils/Log.h"
#include "gpgmm/utils/WindowsUtils.h"

namespace gpgmm::d3d12 {

    template <typename BackendT>
    LogMessage DebugLog(MessageId messageId = MessageId::kUnknown,
                        const BackendT* object = nullptr) {
        return gpgmm::DebugLog(
            messageId, true, (object != nullptr) ? gpgmm::WCharToUTF8(object->GetDebugName()) : "",
            object);
    }

    template <typename BackendT>
    LogMessage InfoLog(MessageId messageId = MessageId::kUnknown,
                       const BackendT* object = nullptr) {
        return gpgmm::InfoLog(messageId, true,
                              (object != nullptr) ? gpgmm::WCharToUTF8(object->GetDebugName()) : "",
                              object);
    }

    template <typename BackendT>
    LogMessage WarnLog(MessageId messageId = MessageId::kUnknown,
                       const BackendT* object = nullptr) {
        return gpgmm::WarnLog(messageId, true,
                              (object != nullptr) ? gpgmm::WCharToUTF8(object->GetDebugName()) : "",
                              object);
    }

    template <typename BackendT>
    LogMessage ErrorLog(MessageId messageId = MessageId::kUnknown,
                        const BackendT* object = nullptr) {
        return gpgmm::ErrorLog(
            messageId, true, (object != nullptr) ? gpgmm::WCharToUTF8(object->GetDebugName()) : "",
            object);
    }

}  // namespace gpgmm::d3d12

#endif  // SRC_GPGMM_D3D12_LOGD3D12_H_
