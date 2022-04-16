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

#ifndef GPGMM_TRACEEVENTPHASE_H_

// Phase indicates the nature of an event entry. E.g. part of a begin/end pair.
#    define TRACE_EVENT_PHASE_BEGIN ('B')
#    define TRACE_EVENT_PHASE_END ('E')
#    define TRACE_EVENT_PHASE_INSTANT ('i')
#    define TRACE_EVENT_PHASE_CREATE_OBJECT ('N')
#    define TRACE_EVENT_PHASE_SNAPSHOT_OBJECT ('O')
#    define TRACE_EVENT_PHASE_DELETE_OBJECT ('D')
#    define TRACE_EVENT_PHASE_METADATA ('M')
#    define TRACE_EVENT_PHASE_COUNTER ('C')

#endif  // GPGMM_TRACEEVENTPHASE_H_
