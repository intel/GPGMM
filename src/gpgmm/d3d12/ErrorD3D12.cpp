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

    std::string GetErrorMessage(HRESULT error) {
        std::wstring wstring = TCharToWString(_com_error(error).ErrorMessage());
        std::stringstream ss;
        ss << WCharToUTF8(wstring.c_str()) << " (0x" << std::hex << std::uppercase
           << std::setfill('0') << std::setw(8) << error << ")";
        return ss.str();
    }

    std::string GetDeviceErrorMessage(ID3D12Device* device, HRESULT error) {
        if (error == DXGI_ERROR_DEVICE_REMOVED) {
            if (device == nullptr) {
                return "Device was not found but removed " + GetErrorMessage(error);
            }

            const HRESULT removedReason = device->GetDeviceRemovedReason();
            std::string removedReasonStr = "Unknown.";
            switch (removedReason) {
                case DXGI_ERROR_DEVICE_HUNG: {
                    removedReasonStr = "HUNG";
                    break;
                }
                case DXGI_ERROR_DEVICE_REMOVED: {
                    removedReasonStr = "REMOVED";
                    break;
                }
                case DXGI_ERROR_DEVICE_RESET: {
                    removedReasonStr = "RESET";
                    break;
                }
                case DXGI_ERROR_DRIVER_INTERNAL_ERROR: {
                    removedReasonStr = "INTERNAL_ERROR";
                    break;
                }
                case DXGI_ERROR_INVALID_CALL: {
                    removedReasonStr = "INVALID_CALL";
                    break;
                }
                case S_OK: {
                    removedReasonStr = "S_OK";
                    break;
                }
                default:
                    break;
            }

            return "Device reason: " + removedReasonStr + " " + GetErrorMessage(removedReason);
        }

        return GetErrorMessage(error);
    }

}  // namespace gpgmm::d3d12
