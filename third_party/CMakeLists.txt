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

# Check if the target was already added with NOT TARGET.
if (NOT TARGET Vulkan-Headers)
    add_subdirectory(${GPGMM_VK_HEADERS_DIR} "${CMAKE_CURRENT_BINARY_DIR}/vulkan-headers")
endif()

################################################################################
# Build subdirectories
################################################################################

# Prevent overriding the GPGMM's compiler/linker settings (or "mismatch detected" LNK2005 errors result)
set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)
add_subdirectory(googletest)

if (GPGMM_ENABLE_VK_LOADER)
    add_subdirectory(${GPGMM_VK_DEPS_DIR}/vulkan-loader/src)
endif()
