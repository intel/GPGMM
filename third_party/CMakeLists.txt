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

################################################################################
# Build subdirectories
################################################################################

include(FetchContent)

set(FETCHCONTENT_BASE_DIR "${GPGMM_THIRD_PARTY_DIR}")

if (GPGMM_ENABLE_TESTS)
  FetchContent_Declare(
    googletest
    GIT_REPOSITORY https://github.com/google/googletest.git
    GIT_TAG        6b74da4757a549563d7c37c8fae3e704662a043b
  )

	# For Windows: Prevent overriding the parent project's compiler/linker settings
	set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)
  FetchContent_MakeAvailable(googletest)

  set(JSONCPP_WITH_TESTS OFF CACHE BOOL "" FORCE)
  set(JSONCPP_WITH_POST_BUILD_UNITTEST OFF CACHE BOOL "" FORCE)
  FetchContent_Declare(
    jsoncpp
    GIT_REPOSITORY https://github.com/open-source-parsers/jsoncpp.git
    GIT_TAG        9059f5cad030ba11d37818847443a53918c327b1
  )
  FetchContent_MakeAvailable(jsoncpp)

	set(BENCHMARK_ENABLE_TESTING OFF CACHE BOOL "" FORCE)
  FetchContent_Declare(
    benchmark
    GIT_REPOSITORY https://github.com/google/benchmark.git
    GIT_TAG        f730846b0a3c0dc0699978846fb14ffb2fad0bdc
  )
  FetchContent_MakeAvailable(benchmark)

endif() # GPGMM_ENABLE_TESTS

if (GPGMM_ENABLE_VK)
  FetchContent_Declare(
    vulkan-headers
    GIT_REPOSITORY https://github.com/KhronosGroup/Vulkan-Headers.git
    GIT_TAG        76f00ef6cbb1886eb1162d1fa39bee8b51e22ee8
  )
  FetchContent_MakeAvailable(vulkan-headers)

  if (GPGMM_ENABLE_VK_LOADER)
    FetchContent_Declare(
      vulkan-loader
      GIT_REPOSITORY https://github.com/KhronosGroup/Vulkan-Loader.git
      GIT_TAG        f503824ff8cbecfe39fb96ac89cbe959355dc311
    )
    FetchContent_MakeAvailable(vulkan-loader)
  endif() # GPGMM_ENABLE_VK_LOADER
endif() # GPGMM_ENABLE_VK
