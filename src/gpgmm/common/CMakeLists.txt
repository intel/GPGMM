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

add_library(gpgmm_common STATIC)
target_sources(gpgmm_common PRIVATE
    "BlockAllocator.h"
    "BuddyBlockAllocator.cpp"
    "BuddyBlockAllocator.h"
    "BuddyMemoryAllocator.cpp"
    "BuddyMemoryAllocator.h"
    "ConditionalMemoryAllocator.cpp"
    "ConditionalMemoryAllocator.h"
    "DedicatedMemoryAllocator.cpp"
    "DedicatedMemoryAllocator.h"
    "Defaults.h"
    "Error.h"
    "EventTraceWriter.cpp"
    "EventTraceWriter.h"
    "EventMessage.cpp"
    "EventMessage.h"
    "IndexedMemoryPool.cpp"
    "IndexedMemoryPool.h"
    "JSONSerializer.cpp"
    "JSONSerializer.h"
    "LIFOMemoryPool.cpp"
    "LIFOMemoryPool.h"
    "Memory.cpp"
    "Memory.h"
    "MemoryAllocation.cpp"
    "MemoryAllocation.h"
    "MemoryAllocator.cpp"
    "MemoryAllocator.h"
    "MemoryCache.h"
    "MemoryPool.cpp"
    "MemoryPool.h"
    "Message.h"
    "PooledMemoryAllocator.cpp"
    "PooledMemoryAllocator.h"
    "SegmentedMemoryAllocator.cpp"
    "SegmentedMemoryAllocator.h"
    "SlabBlockAllocator.cpp"
    "SlabBlockAllocator.h"
    "SlabMemoryAllocator.cpp"
    "SlabMemoryAllocator.h"
    "ThreadPool.cpp"
    "ThreadPool.h"
    "TraceEvent.cpp"
    "TraceEvent.h"
)

target_link_libraries(gpgmm_common PRIVATE gpgmm_common_config)

install(TARGETS gpgmm_common EXPORT gpgmmTargets)
