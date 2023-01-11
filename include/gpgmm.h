// Copyright 2022 The GPGMM Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#ifndef INCLUDE_GPGMM_H_
#define INCLUDE_GPGMM_H_

// gpgmm.h is the GMM interface implemented by GPGMM.
// This file should not be modified by downstream GMM clients or forks of GPGMM.
// Please consider submitting a pull-request to https://github.com/intel/gpgmm.
#include "gpgmm_export.h"

#include <cstdint>

namespace gpgmm {

    /** \struct MemoryAllocatorStats
    Additional information about the memory allocator usage.
    */
    struct MemoryAllocatorStats {
        /** \brief Number of used sub-allocated blocks within the same memory.
         */
        uint32_t UsedBlockCount;

        /** \brief Total size, in bytes, of used sub-allocated blocks.
         */
        uint64_t UsedBlockUsage;

        /** \brief Number of used memory allocations.
         */
        uint32_t UsedMemoryCount;

        /** \brief Total size, in bytes, of used memory.
         */
        uint64_t UsedMemoryUsage;

        /** \brief Total size, in bytes, of free memory.
         */
        uint64_t FreeMemoryUsage;

        /** \brief Cache misses not eliminated by prefetching.
         */
        uint64_t PrefetchedMemoryMisses;

        /** \brief Cache misses eliminated because of prefetching.
         */
        uint64_t PrefetchedMemoryMissesEliminated;

        /** \brief Requested size was NOT cached.
         */
        uint64_t SizeCacheMisses;

        /** \brief Requested size was cached.
         */
        uint64_t SizeCacheHits;

        /** \brief Adds or sums together two infos.
         */
        MemoryAllocatorStats& operator+=(const MemoryAllocatorStats& rhs);
    };

    /** \enum AllocationMethod
    Represents how memory was allocated.
    */
    enum class AllocationMethod {

        /** \brief Not yet allocated or invalid.

        This is an invalid state that assigned temporary before the actual method is known.
        */
        kUndefined = 0,

        /** \brief Not sub-divided.

        One and only one allocation exists for the memory.
        */
        kStandalone = 1,

        /** \brief Sub-divided using one or more allocations.

        Underlying memory will be broken up into one or more memory allocations.
        */
        kSubAllocated = 2,

        /** \brief Sub-divided within a single memory allocation.

        A single memory allocation will be broken into one or more sub-allocations.
        */
        kSubAllocatedWithin = 3,
    };

   /** \enum EVENT_RECORD_FLAGS
    Represents different event categories to record.
    */
    enum EVENT_RECORD_FLAGS {

        /** \brief Record nothing.
         */
        EVENT_RECORD_FLAG_NONE = 0x0,

        /** \brief Record lifetimes of API objects created by GPGMM.
         */
        EVENT_RECORD_FLAG_API_OBJECTS = 0x1,

        /** \brief Record API calls made to GPGMM.
         */
        EVENT_RECORD_FLAG_API_CALLS = 0x2,

        /** \brief Record duration of GPGMM API calls.
         */
        EVENT_RECORD_FLAG_API_TIMINGS = 0x4,

        /** \brief Record metrics made to GPGMM API calls.
         */
        EVENT_RECORD_FLAG_COUNTERS = 0x8,

        /** \brief Record events required for playback.

         Bitwise OR'd combination of EVENT_RECORD_FLAG_API_OBJECTS and
         EVENT_RECORD_FLAG_API_CALLS.
         */
        EVENT_RECORD_FLAG_CAPTURE = 0x3,

        /** \brief Record everything.
         */
        EVENT_RECORD_FLAG_ALL_EVENTS = 0xFF,
    };

    /** \enum EVENT_RECORD_SCOPE
    Represents recording scopes to limit event recording.
    */
    enum EVENT_RECORD_SCOPE {

        /** \brief Scopes events per process (or multiple instances).
         */
        EVENT_RECORD_SCOPE_PER_PROCESS = 0,

        /** \brief Scopes events per instance.
         */
        EVENT_RECORD_SCOPE_PER_INSTANCE = 1,
    };

    /** \struct EVENT_RECORD_OPTIONS
    Represents additional controls for recording.
    */
    struct EVENT_RECORD_OPTIONS {
        /** \brief Flags used to decide what to record.

        Optional parameter. By default, nothing is recorded.
        */
        EVENT_RECORD_FLAGS Flags;

        /** \brief Specifies the scope of the events.

        Optional parameter. By default, recording is per process.
        */
        EVENT_RECORD_SCOPE EventScope;

        /** \brief Record detailed timing events.

        Optional parameter. By default, detailed timing events are disabled.
        */
        bool UseDetailedTimingEvents;

        /** \brief Path to trace file.

        Optional parameter. By default, a trace file is created for you.
        */
        const char* TraceFile;
    };

}  // namespace gpgmm

#endif  // INCLUDE_GPGMM_H_
