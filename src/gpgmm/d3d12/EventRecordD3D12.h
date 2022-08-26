// Copyright 2021 The GPGMM Authors
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

#ifndef GPGMM_D3D12_EVENTRECORDD3D12_H_
#define GPGMM_D3D12_EVENTRECORDD3D12_H_

#include "gpgmm/d3d12/d3d12_platform.h"
#include "gpgmm/utils/EnumFlags.h"

#include <string>

namespace gpgmm::d3d12 {

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

    DEFINE_ENUM_FLAG_OPERATORS(EVENT_RECORD_FLAGS)

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

        /** \brief Minimum severity level to record messages.

        Messages with lower severity will be ignored.

        Optional parameter. By default, the minimum severity level is WARN.
        */
        D3D12_MESSAGE_SEVERITY MinMessageLevel;

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
        std::string TraceFile;
    };

}  // namespace gpgmm::d3d12

#endif  // GPGMM_D3D12_EVENTRECORDD3D12_H_
