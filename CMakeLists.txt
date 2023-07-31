# Copyright 2020 The Dawn Authors
# Copyright 2022 The GPGMM Authors
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

cmake_minimum_required(VERSION 3.14)

project(
  GPGMM
  DESCRIPTION "GPGMM, a General-Purpose GPU Memory Management Library"
  LANGUAGES C CXX
)

# USE_FOLDERS allows organizing CMake into a hierarchy of folders using the
# FOLDER property to name them.
set_property(GLOBAL PROPERTY USE_FOLDERS ON)

set(CMAKE_CXX_STANDARD 17)

if(NOT CMAKE_BUILD_TYPE)
  message(WARNING "CMAKE_BUILD_TYPE not set, forcing it to Debug")
  set(CMAKE_BUILD_TYPE "Debug" CACHE STRING
    "Build type (Debug, Release, RelWithDebInfo, MinSizeRel)" FORCE)
endif()

# Only <PROJECT-NAME>_SOURCE_DIR is created by the project() command above.
set(GPGMM_ROOT_DIR "${GPGMM_SOURCE_DIR}")
set(GPGMM_INCLUDE_DIR "${GPGMM_ROOT_DIR}/include")

# ###############################################################################
# Configuration options
# ###############################################################################

# option_if_not_defined(name description default)
# Behaves like:
# option(name description default)
# If a variable is not already defined with the given name, otherwise the
# function does nothing.
function(option_if_not_defined name description default)
  if(NOT DEFINED ${name})
    option(${name} ${description} ${default})
  endif()
endfunction()

# set_if_not_defined(name value description)
# Behaves like:
# set(${name} ${value} CACHE STRING ${description})
# If a variable is not already defined with the given name, otherwise the
# function does nothing.
function(set_if_not_defined name value description)
  if(NOT DEFINED ${name})
    set(${name} ${value} CACHE STRING ${description})
  endif()
endfunction()

# Default values for the backend-enabling options
set(ENABLE_D3D12 OFF)
set(ENABLE_VK OFF)

if(WIN32)
  set(ENABLE_D3D12 ON)

  if(NOT WINDOWS_STORE)
    # Enable Vulkan in win32 compilation only
    # since UWP only supports d3d
    set(ENABLE_VK ON)
  endif()
elseif(UNIX)
  set(ENABLE_VK ON)
endif()

# Uses our built version of the Vulkan loader on platforms where we can't
# assume to have one present at the system level.
set(ENABLE_VK_LOADER OFF)

if(APPLE OR(UNIX AND NOT ANDROID))
  if(ENABLE_VK)
    set(ENABLE_VK_LOADER ON)
  endif()
endif()

option_if_not_defined(GPGMM_STANDALONE "When building from GPGMM's repository" ON)

option_if_not_defined(GPGMM_ENABLE_TESTS "Enables compilation of tests" ON)
option_if_not_defined(GPGMM_ENABLE_D3D12 "Enable compilation of the D3D12 backend" ${ENABLE_D3D12})
option_if_not_defined(GPGMM_ENABLE_VK "Enable compilation of the Vulkan backend" ${ENABLE_VK})
option_if_not_defined(GPGMM_ENABLE_VK_STATIC_FUNCTIONS "Links Vulkan functions by statically importing them" OFF)
option_if_not_defined(GPGMM_ENABLE_VK_LOADER "Enables compilation of Vulkan loader" ${ENABLE_VK_LOADER})
option_if_not_defined(GPGMM_ENABLE_VK_USE_SDK "Enable compilation of the Vulkan backend by using the installed Vulkan SDK." OFF)

set_if_not_defined(GPGMM_THIRD_PARTY_DIR "${GPGMM_SOURCE_DIR}/third_party" "Directory in which to find third-party dependencies.")
set_if_not_defined(GPGMM_VK_DEPS_DIR "${GPGMM_THIRD_PARTY_DIR}/vulkan-deps" "Directory in which to find vulkan-deps")
set_if_not_defined(GPGMM_VK_HEADERS_DIR "${GPGMM_VK_DEPS_DIR}/vulkan-headers/src" "Directory in which to find Vulkan-Headers")

option_if_not_defined(GPGMM_ALWAYS_ASSERT "Enable assertions on all build types" OFF)
option_if_not_defined(GPGMM_FORCE_TRACING "Enables event tracing even in release builds" OFF)
option_if_not_defined(GPGMM_ENABLE_DEVICE_LEAK_CHECKS "Enables checking of device leaks" OFF)
option_if_not_defined(GPGMM_ENABLE_ALLOCATOR_LEAK_CHECKS "Enables checking of allocator leaks" OFF)
option_if_not_defined(GPGMM_ENABLE_ASSERT_ON_WARNING "Enables ASSERT on severity functionality" OFF)
option_if_not_defined(GPGMM_DISABLE_SIZE_CACHE "Enables warming of caches with common resource sizes" OFF)
option_if_not_defined(GPGMM_ENABLE_MEMORY_ALIGN_CHECKS "Enables checking of resource alignment." OFF)
option_if_not_defined(GPGMM_ENABLE_LOGGING_INTERNAL "Enables log messages for internal objects." OFF)

if(GPGMM_ENABLE_TESTS)
  # Vulkan tests require static linking.
  if (GPGMM_ENABLE_VK)
    set(GPGMM_ENABLE_VK_STATIC_FUNCTIONS ON)
  endif()
  enable_testing()
endif()

# Use the Vulkan loader if the SDK isn't available.
if (GPGMM_ENABLE_VK_STATIC_FUNCTIONS)
  if (NOT ${GPGMM_ENABLE_VK_USE_SDK})
    set(GPGMM_ENABLE_VK_LOADER ON)
  endif()
endif()

# ###############################################################################
# GPGMM's public and common "configs"
# ###############################################################################
set(GPGMM_INCLUDE_DIRS
  "${GPGMM_INCLUDE_DIR}"
)

# Where GPGMM public .h files can be found.
# Sets directory for header files to be searched.
include_directories(${GPGMM_INCLUDE_DIRS})

add_library(gpgmm_public_config INTERFACE)
target_include_directories(gpgmm_public_config INTERFACE "${GPGMM_INCLUDE_DIRS}")

add_library(gpgmm_common_config INTERFACE)
target_include_directories(gpgmm_common_config INTERFACE $<BUILD_INTERFACE:${GPGMM_ROOT_DIR}/src>)

install(TARGETS gpgmm_common_config EXPORT gpgmmTargets)

# Compile definitions for the common config
if(GPGMM_ALWAYS_ASSERT)
  target_compile_definitions(gpgmm_common_config INTERFACE "GPGMM_ENABLE_ASSERTS")
else()
  target_compile_definitions(gpgmm_common_config INTERFACE
    $<$<CONFIG:Debug>:GPGMM_ENABLE_ASSERTS>
  )
endif()

if(GPGMM_ENABLE_D3D12)
  target_compile_definitions(gpgmm_common_config INTERFACE "GPGMM_ENABLE_D3D12")
endif()

if(GPGMM_ENABLE_VK)
  target_compile_definitions(gpgmm_common_config INTERFACE "GPGMM_ENABLE_VK")
endif()

if(NOT GPGMM_FORCE_TRACING)
  target_compile_definitions(gpgmm_common_config INTERFACE
    $<$<NOT:$<CONFIG:Debug>>:GPGMM_DISABLE_TRACING>
  )
endif()

if(GPGMM_ENABLE_DEVICE_LEAK_CHECKS)
  target_compile_definitions(gpgmm_common_config INTERFACE "GPGMM_ENABLE_DEVICE_LEAK_CHECKS")
endif()

if(GPGMM_ENABLE_ALLOCATOR_LEAK_CHECKS)
  target_compile_definitions(gpgmm_common_config INTERFACE "GPGMM_ENABLE_ALLOCATOR_LEAK_CHECKS")
endif()

if(GPGMM_DISABLE_SIZE_CACHE)
  target_compile_definitions(gpgmm_common_config INTERFACE "GPGMM_DISABLE_SIZE_CACHE")
endif()

if(GPGMM_ENABLE_MEMORY_ALIGN_CHECKS)
  target_compile_definitions(gpgmm_common_config INTERFACE "GPGMM_ENABLE_MEMORY_ALIGN_CHECKS")
else()
  target_compile_definitions(gpgmm_common_config INTERFACE
    $<$<CONFIG:Debug>:GPGMM_ENABLE_MEMORY_ALIGN_CHECKS>
  )
endif()

if(WIN32)
  target_compile_definitions(gpgmm_common_config INTERFACE "NOMINMAX" "WIN32_LEAN_AND_MEAN")
endif()

# ###############################################################################
# Build subdirectories
# ###############################################################################
add_subdirectory(third_party)
add_subdirectory(src/gpgmm)

# Tests use GPGMM internals (eg. gpgmm_common, gpgmm_utils, etc) which are never
# exported and must be statically built.
if(GPGMM_ENABLE_TESTS AND NOT BUILD_SHARED_LIBS)
  add_subdirectory(src/tests)
endif()

if(GPGMM_STANDALONE)
  add_subdirectory(src/samples)
endif()

# ###############################################################################
# Install GPGMM
# ###############################################################################
include(${CMAKE_CURRENT_SOURCE_DIR}/cmake/install.cmake)
