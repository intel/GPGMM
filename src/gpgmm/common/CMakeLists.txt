# Copyright 2020 The Dawn Authors
# Copyright 2021 The GPGMM Authors
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

add_library(gpgmm_common STATIC)
target_sources(gpgmm_common PRIVATE
  "Assert.cpp"
  "Assert.h"
  "Compiler.h"
  "Flags.h"
  "JSONEncoder.cpp"
  "JSONEncoder.h"
  "Limits.h"
  "LinkedList.h"
  "Log.cpp"
  "Log.h"
  "Math.cpp"
  "Math.h"
  "Platform.h"
  "PlatformTime.cpp"
  "PlatformTime.h"
  "RefCount.cpp"
  "RefCount.h"
  "SystemUtils.cpp"
  "SystemUtils.h"
  "Utils.cpp"
  "Utils.h"
)

if (WIN32)
    target_sources(gpgmm_common PRIVATE
        "WindowsTime.cpp"
    )
endif()

target_link_libraries(gpgmm_common PRIVATE gpgmm_common_config)
