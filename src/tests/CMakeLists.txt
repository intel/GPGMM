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

target_include_directories(gpgmm_unittests PRIVATE "${GPGMM_ROOT_DIR}/src")
target_link_libraries(gpgmm_unittests gpgmm gtest)
