cmake_minimum_required(VERSION 3.14)

project(D3D12ProjectTemplate LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)

include(FetchContent)
FetchContent_Declare(gpgmm
  GIT_REPOSITORY https://github.com/intel/gpgmm.git
  GIT_TAG main
)

set(GPGMM_ENABLE_VK "OFF")
set(GPGMM_ENABLE_TESTS "OFF")
set(GPGMM_STANDALONE "OFF")

FetchContent_MakeAvailable(gpgmm)

add_executable(D3D12ProjectTemplate)

target_sources(D3D12ProjectTemplate PRIVATE
    "main.cpp"
)

# Required to use D3D12.
target_link_libraries(D3D12ProjectTemplate PRIVATE
    d3d12.lib
    dxgi.lib
)

target_link_libraries(D3D12ProjectTemplate PRIVATE gpgmm)
