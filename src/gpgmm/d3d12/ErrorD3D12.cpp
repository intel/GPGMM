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

#include "gpgmm/d3d12/ErrorD3D12.h"

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

}  // namespace gpgmm::d3d12
