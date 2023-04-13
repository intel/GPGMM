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

#ifndef GPGMM_D3D12_LOGD3D12_H_
#define GPGMM_D3D12_LOGD3D12_H_

#include "gpgmm/common/EventMessage.h"
#include "gpgmm/utils/WindowsUtils.h"

namespace gpgmm::d3d12 {

    template <typename BackendT>
    LogMessage DebugLog(const BackendT* object, MessageId messageId = MessageId::kUnknown) {
        return gpgmm::DebugLog(messageId, true, gpgmm::WCharToUTF8(object->GetDebugName()), object);
    }

    template <typename BackendT>
    LogMessage InfoLog(const BackendT* object, MessageId messageId = MessageId::kUnknown) {
        return gpgmm::InfoLog(messageId, true, gpgmm::WCharToUTF8(object->GetDebugName()), object);
    }

    template <typename BackendT>
    LogMessage WarnLog(const BackendT* object, MessageId messageId = MessageId::kUnknown) {
        return gpgmm::WarnLog(messageId, true, gpgmm::WCharToUTF8(object->GetDebugName()), object);
    }

    template <typename BackendT>
    LogMessage ErrorLog(const BackendT* object, MessageId messageId = MessageId::kUnknown) {
        return gpgmm::ErrorLog(messageId, true, gpgmm::WCharToUTF8(object->GetDebugName()), object);
    }

    template <typename BackendT>
    EventMessage DebugEvent(const BackendT* object, MessageId messageId = MessageId::kUnknown) {
        return gpgmm::DebugEvent(messageId, true, gpgmm::WCharToUTF8(object->GetDebugName()),
                                 object);
    }

    template <typename BackendT>
    EventMessage InfoEvent(const BackendT* object, MessageId messageId = MessageId::kUnknown) {
        return gpgmm::InfoEvent(messageId, true, gpgmm::WCharToUTF8(object->GetDebugName()),
                                object);
    }

    template <typename BackendT>
    EventMessage WarnEvent(const BackendT* object, MessageId messageId = MessageId::kUnknown) {
        return gpgmm::WarnEvent(messageId, true, gpgmm::WCharToUTF8(object->GetDebugName()),
                                object);
    }

    template <typename BackendT>
    EventMessage ErrorEvent(const BackendT* object, MessageId messageId = MessageId::kUnknown) {
        return gpgmm::ErrorEvent(messageId, true, gpgmm::WCharToUTF8(object->GetDebugName()),
                                 object);
    }

}  // namespace gpgmm::d3d12

#endif  // GPGMM_D3D12_LOGD3D12_H_
