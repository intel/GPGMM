# Copyright 2022 The GPGMM Authors
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# Provide the configure_package_config_file function below.
include(CMakePackageConfigHelpers)

if(NOT DEFINED CMAKE_INSTALL_LIBDIR)
  set(CMAKE_INSTALL_LIBDIR lib)
endif()

if(NOT DEFINED CMAKE_INSTALL_BINDIR)
  set(CMAKE_INSTALL_BINDIR bin)
endif()

install(TARGETS gpgmm
    EXPORT gpgmmTargets
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
)

# vulkan-headers must be rolled to export gpgmm.
# TODO: Remove check after rolling vulkan-headers.
if(GPGMM_ENABLE_VK)
    message(WARNING "GPGMM_ENABLE_VK is not supported for install.cmake" )
    return()
endif()

# Configure then config input file with the targets to be exported.
install(EXPORT gpgmmTargets
    DESTINATION lib/cmake/gpgmm
    FILE gpgmmTargets.cmake
)

# Generate the config output file that includes the exports.
configure_package_config_file(
    "${CMAKE_CURRENT_SOURCE_DIR}/cmake/gpgmmConfig.cmake.in"
    "${CMAKE_CURRENT_BINARY_DIR}/gpgmmConfig.cmake"
    INSTALL_DESTINATION "lib/cmake/gpgmm"
    NO_CHECK_REQUIRED_COMPONENTS_MACRO
)

# Provide a relocatable configuration file for gpgmm.
install(
    FILES
        ${CMAKE_CURRENT_BINARY_DIR}/gpgmmConfig.cmake
    DESTINATION
        lib/cmake/gpgmm
)

# Allow any parent project to build with the exported target.
export(EXPORT gpgmmTargets
    FILE "${CMAKE_CURRENT_BINARY_DIR}/gpgmmTargets.cmake"
)

export(PACKAGE gpgmm)
