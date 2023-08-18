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

#include "gpgmm/d3d12/ErrorD3D12.h"

#include "gpgmm/utils/Log.h"
#include "gpgmm/utils/WindowsUtils.h"

#include <comdef.h>
#include <iomanip>
#include <sstream>

namespace gpgmm::d3d12 {

    ErrorCode GetErrorCode(HRESULT error) {
        switch (error) {
            case S_OK:
                return ErrorCode::kNone;
            case E_INVALIDARG:
            case E_POINTER:
                return ErrorCode::kInvalidArgument;
            case E_UNEXPECTED:
                return ErrorCode::kBadOperation;
            case E_NOTIMPL:
                return ErrorCode::kUnsupported;
            case E_OUTOFMEMORY:
                return ErrorCode::kOutOfMemory;
            case E_FAIL:
            default:
                return ErrorCode::kUnknown;
        }
    }

    HRESULT GetErrorResult(ErrorCode error) {
        switch (error) {
            case ErrorCode::kNone:
                return S_OK;
            case ErrorCode::kInvalidArgument:
                return E_INVALIDARG;
            case ErrorCode::kBadOperation:
                return E_UNEXPECTED;
            case ErrorCode::kUnsupported:
                return E_NOTIMPL;
            case ErrorCode::kOutOfMemory:
                return E_OUTOFMEMORY;
            case ErrorCode::kUnknown:
            case ErrorCode::kAllocationFailed:
            default:
                return E_FAIL;
        }
    }

    bool IsErrorResultFatal(HRESULT error) {
        switch (error) {
            case E_UNEXPECTED:
                return true;
            default:
                return false;
        }
    }

    std::string GetErrorResultToString(HRESULT error) noexcept {
        std::wstring wstring = TCharToWString(_com_error(error).ErrorMessage());
        std::stringstream ss;
        ss << WCharToUTF8(wstring.c_str()) << " (0x" << std::hex << std::uppercase
           << std::setfill('0') << std::setw(8) << error << ")";
        return ss.str();
    }

    std::string GetErrorResultWithRemovalReason(HRESULT error, ID3D12Device* device) {
        if (error == DXGI_ERROR_DEVICE_REMOVED) {
            if (device == nullptr) {
                return "Device was not found but removed " + GetErrorResultToString(error);
            }
            return GetErrorResultToString(error) +
                   " with reason: " + GetErrorResultToString(device->GetDeviceRemovedReason());
        }
        return GetErrorResultToString(error);
    }

}  // namespace gpgmm::d3d12
