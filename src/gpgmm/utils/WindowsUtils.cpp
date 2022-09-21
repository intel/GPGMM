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

#include "WindowsUtils.h"

#include "Assert.h"

#include <memory>
#include <string>

#include <windows.h>  // must include before stringapiset.

#include <stringapiset.h>

namespace gpgmm {

    std::wstring TCharToWString(const wchar_t* const str) {
        return str;
    }

    std::wstring TCharToWString(const char* const str) {
        std::string strFrom(str);
        int requiredSize =
            MultiByteToWideChar(CP_UTF8, 0, &strFrom[0], static_cast<int>(strFrom.size()), NULL, 0);

        std::wstring wstrTo(requiredSize, 0);
        MultiByteToWideChar(CP_UTF8, 0, &str[0], static_cast<int>(strFrom.size()), &wstrTo[0],
                            requiredSize);
        return wstrTo;
    }

    std::string WCharToUTF8(const wchar_t* str) {
        int requiredSize = WideCharToMultiByte(CP_UTF8, 0, str, -1, nullptr, 0, nullptr, nullptr);
        std::string result;
        result.resize(requiredSize - 1);
        WideCharToMultiByte(CP_UTF8, 0, str, -1, &result[0], requiredSize, nullptr, nullptr);
        return result;
    }

}  // namespace gpgmm
