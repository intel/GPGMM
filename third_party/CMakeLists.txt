# Copyright 2022 The GPGMM Authors
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

# Current revision of source-package.
set(GPGMM_GOOGLETEST_REVISION 6b74da4757a549563d7c37c8fae3e704662a043b)
set(GPGMM_JSONCPP_REVISION 9059f5cad030ba11d37818847443a53918c327b1)
set(GPGMM_BENCHMARK_REVISION f730846b0a3c0dc0699978846fb14ffb2fad0bdc)
set(GPGMM_VULKAN_HEADERS_REVISION 9f73b931f402f23554a60015924e7e35c7047487)
set(GPGMM_VULKAN_LOADER_REVISION 9a45e5a4ab79b81e27e1417ca65d53ecfe57ba37)

if (GPGMM_ENABLE_TESTS)
  FetchContent_Declare(
    googletest
    GIT_REPOSITORY https://github.com/google/googletest.git
    GIT_TAG        ${GPGMM_GOOGLETEST_REVISION}
  )

	# For Windows: Prevent overriding the parent project's compiler/linker settings
	set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)
  FetchContent_MakeAvailable(googletest)

  set(JSONCPP_WITH_TESTS OFF CACHE BOOL "" FORCE)
  set(JSONCPP_WITH_POST_BUILD_UNITTEST OFF CACHE BOOL "" FORCE)
  FetchContent_Declare(
    jsoncpp
    GIT_REPOSITORY https://github.com/open-source-parsers/jsoncpp.git
    GIT_TAG        ${GPGMM_JSONCPP_REVISION}
  )
  FetchContent_MakeAvailable(jsoncpp)

	set(BENCHMARK_ENABLE_TESTING OFF CACHE BOOL "" FORCE)
  FetchContent_Declare(
    benchmark
    GIT_REPOSITORY https://github.com/google/benchmark.git
    GIT_TAG        ${GPGMM_BENCHMARK_REVISION}
  )
  FetchContent_MakeAvailable(benchmark)

endif() # GPGMM_ENABLE_TESTS

if (GPGMM_ENABLE_VK)
	if (GPGMM_ENABLE_VK_USE_SDK)
		message(INFO "Using installed Vulkan SDK")
		find_package(Vulkan REQUIRED)

    set(GPGMM_VK_INCLUDE_DIR ${Vulkan_INCLUDE_DIRS} CACHE STRING "" FORCE)
		set(GPGMM_VK_LIBRARIES_DIR ${Vulkan_LIBRARIES} CACHE STRING "" FORCE)
    message(INFO "Using Vulkan include directory: ${GPGMM_VK_INCLUDE_DIR}")
    message(INFO "Using Vulkan library directory: ${GPGMM_VK_LIBRARIES_DIR}")

	else()
		FetchContent_Declare(
			vulkan-headers
			GIT_REPOSITORY https://github.com/KhronosGroup/Vulkan-Headers.git
			GIT_TAG ${GPGMM_VULKAN_HEADERS_REVISION}
		)
		FetchContent_MakeAvailable(vulkan-headers)

		if (GPGMM_ENABLE_VK_LOADER)
			FetchContent_Declare(
				vulkan-loader
				GIT_REPOSITORY https://github.com/KhronosGroup/Vulkan-Loader.git
				GIT_TAG ${GPGMM_VULKAN_LOADER_REVISION}
			)
			FetchContent_MakeAvailable(vulkan-loader)

		endif() # GPGMM_ENABLE_VK_LOADER
	endif() # GPGMM_ENABLE_VK_USE_SDK

endif() # GPGMM_ENABLE_VK
