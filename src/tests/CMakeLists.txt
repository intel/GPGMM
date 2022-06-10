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
