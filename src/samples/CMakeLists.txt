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

if (GPGMM_ENABLE_D3D12)
  add_executable(D3D12Sample)

  target_sources(D3D12Sample PRIVATE
        "D3D12Sample.cpp"
  )

	# Required to use D3D12.
  target_link_libraries(D3D12Sample PRIVATE
     d3d12.lib
		 dxgi.lib
  )

	# Target explaination:
  # gpgmm_common_config target fixes duplicate min/max symbol error (on Windows).
	# gpgmm_public_config target adds include paths to src/ and src/include.
  # gpgmm is the main library target.
	target_link_libraries(D3D12Sample PRIVATE
    gpgmm_common_config
    gpgmm_public_config
    gpgmm
  )
endif()
