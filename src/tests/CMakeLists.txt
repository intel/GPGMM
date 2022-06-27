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

###############################################################################
# Unit tests
###############################################################################

add_executable(gpgmm_unittests)

target_link_libraries(gpgmm_unittests PRIVATE
   gpgmm_common_config
)

target_sources(gpgmm_unittests PRIVATE
  "DummyMemoryAllocator.h"
  "unittests/BuddyBlockAllocatorTests.cpp"
  "unittests/ConditionalMemoryAllocatorTests.cpp"
  "unittests/EventTraceWriterTests.cpp"
  "unittests/FlagsTests.cpp"
  "unittests/LinkedListTests.cpp"
  "unittests/MathTests.cpp"
  "unittests/MemoryAllocatorTests.cpp"
  "unittests/MemoryCacheTests.cpp"
  "unittests/MemoryPoolTests.cpp"
  "unittests/PooledMemoryAllocatorTests.cpp"
  "unittests/RefCountTests.cpp"
  "unittests/SegmentedMemoryAllocatorTests.cpp"
  "unittests/SlabBlockAllocatorTests.cpp"
  "unittests/SlabMemoryAllocatorTests.cpp"
  "unittests/UtilsTest.cpp"
  "UnittestsMain.cpp"
)

target_link_libraries(gpgmm_unittests PRIVATE
   gpgmm
   gtest
)

###############################################################################
# End2End tests
###############################################################################

add_executable(gpgmm_end2end_tests)

target_sources(gpgmm_end2end_tests PRIVATE
    "GPGMMTest.cpp"
    "GPGMMTest.h"
    "End2EndTestsMain.cpp"
)

target_link_libraries(gpgmm_end2end_tests
  PRIVATE gpgmm_common_config
)

if (GPGMM_ENABLE_D3D12)
  target_sources(gpgmm_end2end_tests PRIVATE
      "D3D12Test.cpp"
      "D3D12Test.h"
      "end2end/D3D12IUnknownImplTests.cpp"
      "end2end/D3D12ResidencyManagerTests.cpp"
      "end2end/D3D12ResourceAllocatorTests.cpp"
  )

  target_link_libraries(gpgmm_end2end_tests PRIVATE
     d3d12.lib
     dxgi.lib
  )
endif()

if (GPGMM_ENABLE_VK)
  target_sources(gpgmm_end2end_tests PRIVATE
      "VKTest.cpp"
      "VKTest.h"
      "end2end/VKResourceAllocatorTests.cpp"
  )

  target_link_libraries(gpgmm_end2end_tests PRIVATE
     Vulkan::Vulkan
  )
endif()

target_link_libraries(gpgmm_end2end_tests PRIVATE
     gpgmm
     gtest
)

###############################################################################
# Capture replay tests
###############################################################################

add_executable(gpgmm_capture_replay_tests)

set(TRACE_INDEX_FILE_NAME "traces.json")
set(TRACE_INPUT_DIR "${CMAKE_CURRENT_BINARY_DIR}/capture_replay_tests/traces")
set(TRACE_INDEX_OUTPUT_PATH "${CMAKE_CURRENT_BINARY_DIR}/${TRACE_INDEX_FILE_NAME}")

add_custom_command(
  TARGET gpgmm_capture_replay_tests PRE_BUILD
  COMMAND python3 ${GPGMM_ROOT_DIR}/scripts/generate_capture_replay_trace_index.py --traces_dir "${TRACE_INPUT_DIR}" --trace_index "${TRACE_INDEX_OUTPUT_PATH}"
  COMMENT "Generating capture replay trace index"
  VERBATIM
)

target_compile_definitions(gpgmm_capture_replay_tests PRIVATE -DGPGMM_CAPTURE_REPLAY_TESTS_TRACE_INDEX="${TRACE_INDEX_OUTPUT_PATH}")

target_sources(gpgmm_capture_replay_tests PRIVATE
    "GPGMMTest.cpp"
    "GPGMMTest.h"
    "capture_replay_tests/GPGMMCaptureReplayTests.cpp"
    "capture_replay_tests/GPGMMCaptureReplayTests.h"
    "CaptureReplayTestsMain.cpp"
)

target_link_libraries(gpgmm_capture_replay_tests
  PRIVATE gpgmm_common_config
)

if (GPGMM_ENABLE_D3D12)
  target_sources(gpgmm_capture_replay_tests PRIVATE
      "D3D12Test.cpp"
      "D3D12Test.h"
      "capture_replay_tests/D3D12EventTraceReplay.cpp"
  )

  target_link_libraries(gpgmm_capture_replay_tests PRIVATE
     d3d12.lib
     dxgi.lib
  )
endif()

target_link_libraries(gpgmm_capture_replay_tests PRIVATE
     gpgmm
     gtest
     jsoncpp_static
)

###############################################################################
# Perf tests
###############################################################################

add_executable(gpgmm_perftests)

target_link_libraries(gpgmm_perftests PRIVATE
   gpgmm_common_config
)

target_sources(gpgmm_perftests PRIVATE
    "DummyMemoryAllocator.h"
    "perftests/MemoryAllocatorPerfTests.cpp"
)

target_link_libraries(gpgmm_perftests PRIVATE
   gpgmm
   benchmark
)

################################################################################
# Run test executions by `make test` or `cmake --build . --target RUN_TESTS`
# for Linux or Windows, respectively.
################################################################################
add_test(NAME gpgmm_test_unittests COMMAND gpgmm_unittests)
add_test(NAME gpgmm_test_end2end_tests COMMAND gpgmm_end2end_tests)
add_test(NAME gpgmm_test_capture_replay_tests COMMAND gpgmm_capture_replay_tests)
