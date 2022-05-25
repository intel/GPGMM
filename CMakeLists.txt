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

cmake_minimum_required(VERSION 3.10)

project(
    GPGMM
    DESCRIPTION "GPGMM, a General-Purpose GPU Memory Management Library"
    LANGUAGES C CXX
)

# USE_FOLDERS allows organizing CMake into a hierarchy of folders using the
# FOLDER property to name them.
set_property(GLOBAL PROPERTY USE_FOLDERS ON)

if(NOT CMAKE_BUILD_TYPE)
    message(WARNING "CMAKE_BUILD_TYPE not set, forcing it to Debug")
    set(CMAKE_BUILD_TYPE "Debug" CACHE STRING
        "Build type (Debug, Release, RelWithDebInfo, MinSizeRel)" FORCE)
endif()

# Only <PROJECT-NAME>_SOURCE_DIR is created by the project() command above.
set(GPGMM_ROOT_DIR "${GPGMM_SOURCE_DIR}")
set(GPGMM_INCLUDE_DIR "${GPGMM_ROOT_DIR}/src/include")

################################################################################
# Configuration options
################################################################################

# option_if_not_defined(name description default)
# Behaves like:
#   option(name description default)
# If a variable is not already defined with the given name, otherwise the
# function does nothing.
function (option_if_not_defined name description default)
    if(NOT DEFINED ${name})
        option(${name} ${description} ${default})
    endif()
endfunction()

# set_if_not_defined(name value description)
# Behaves like:
#   set(${name} ${value} CACHE STRING ${description})
# If a variable is not already defined with the given name, otherwise the
# function does nothing.
function (set_if_not_defined name value description)
    if(NOT DEFINED ${name})
        set(${name} ${value} CACHE STRING ${description})
    endif()
endfunction()

# Default values for the backend-enabling options
set(ENABLE_D3D12 OFF)
set(ENABLE_VK OFF)
if (WIN32)
    set(ENABLE_D3D12 ON)
    if (NOT WINDOWS_STORE)
        # Enable Vulkan in win32 compilation only
        # since UWP only supports d3d
        set(ENABLE_VK ON)
    endif()
elseif(UNIX)
    set(ENABLE_VK ON)
endif()

option_if_not_defined(GPGMM_ENABLE_D3D12 "Enable compilation of the D3D12 backend" ${ENABLE_D3D12})
option_if_not_defined(GPGMM_ENABLE_VK "Enable compilation of the Vulkan backend" ${ENABLE_VK})

set_if_not_defined(GPGMM_THIRD_PARTY_DIR "${GPGMM_SOURCE_DIR}/third_party" "Directory in which to find third-party dependencies.")
set_if_not_defined(GPGMM_VK_DEPS_DIR "${GPGMM_THIRD_PARTY_DIR}/vulkan-deps" "Directory in which to find vulkan-deps")
set_if_not_defined(GPGMM_VK_HEADERS_DIR "${GPGMM_VK_DEPS_DIR}/vulkan-headers/src" "Directory in which to find Vulkan-Headers")
set_if_not_defined(GPGMM_VK_TOOLS_DIR "${GPGMM_VK_DEPS_DIR}/vulkan-tools/src" "Directory in which to find Vulkan-Tools")

option_if_not_defined(GPGMM_ALWAYS_ASSERT "Enable assertions on all build types" OFF)

################################################################################
# GPGMM's public and common "configs"
################################################################################

add_library(gpgmm_public_config INTERFACE)
target_include_directories(gpgmm_public_config INTERFACE
    "${GPGMM_ROOT_DIR}/src"
    "${GPGMM_ROOT_DIR}/src/include"
)

add_library(gpgmm_common_config INTERFACE)
target_link_libraries(gpgmm_common_config INTERFACE gpgmm_public_config)

# Compile definitions for the common config
if (GPGMM_ALWAYS_ASSERT OR $<CONFIG:Debug>)
    # TODO: rename definition
    target_compile_definitions(gpgmm_common_config INTERFACE "GPGMM_ENABLE_ASSERTS")
endif()
if (GPGMM_ENABLE_D3D12)
    target_compile_definitions(gpgmm_common_config INTERFACE "GPGMM_ENABLE_D3D12")
endif()
if (GPGMM_ENABLE_VK)
    target_compile_definitions(gpgmm_common_config INTERFACE "GPGMM_ENABLE_VK")
endif()
if (WIN32)
    target_compile_definitions(gpgmm_common_config INTERFACE "NOMINMAX" "WIN32_LEAN_AND_MEAN")
endif()

set(CMAKE_CXX_STANDARD "14")

################################################################################
# Build subdirectories
################################################################################
add_subdirectory(third_party)
add_subdirectory(src/gpgmm)