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

#include "gpgmm/d3d12/UtilsD3D12.h"

#include "gpgmm/utils/Math.h"
#include "gpgmm/utils/WindowsUtils.h"

namespace gpgmm::d3d12 {

    LogSeverity GetLogSeverity(D3D12_MESSAGE_SEVERITY messageSeverity) {
        switch (messageSeverity) {
            case D3D12_MESSAGE_SEVERITY_CORRUPTION:
            case D3D12_MESSAGE_SEVERITY_ERROR:
                return LogSeverity::Error;
            case D3D12_MESSAGE_SEVERITY_WARNING:
                return LogSeverity::Warning;
            case D3D12_MESSAGE_SEVERITY_INFO:
                return LogSeverity::Info;
            case D3D12_MESSAGE_SEVERITY_MESSAGE:
                return LogSeverity::Debug;
            default:
                UNREACHABLE();
                return LogSeverity::Debug;
        }
    }

    bool IsDepthFormat(DXGI_FORMAT format) {
        // Depth formats in order of appearance.
        // https://docs.microsoft.com/en-us/windows/win32/api/dxgiformat/ne-dxgiformat-dxgi_format
        switch (format) {
            case DXGI_FORMAT_D32_FLOAT_S8X24_UINT:
            case DXGI_FORMAT_D32_FLOAT:
            case DXGI_FORMAT_D24_UNORM_S8_UINT:
            case DXGI_FORMAT_D16_UNORM:
                return true;
            default:
                return false;
        }
    }

    bool IsMultiPlanarFormat(DXGI_FORMAT format) {
        switch (format) {
            case DXGI_FORMAT_D32_FLOAT_S8X24_UINT:
            case DXGI_FORMAT_D24_UNORM_S8_UINT:
            case DXGI_FORMAT_NV12:
                return true;
            default:
                return false;
        }
    }

    uint64_t GetTileCount(const D3D12_RESOURCE_DESC& resourceDescriptor,
                          const D3D12_TILE_SHAPE& tileShape) {
        return (RoundUp(resourceDescriptor.Width, tileShape.WidthInTexels) /
                tileShape.WidthInTexels) *
               (RoundUp(resourceDescriptor.Height, tileShape.HeightInTexels) /
                tileShape.HeightInTexels) *
               (RoundUp(resourceDescriptor.DepthOrArraySize, tileShape.DepthInTexels) /
                tileShape.DepthInTexels);
    }

    // Returns number of bits per texel "unit" (single texel or 2D texel "block").
    uint32_t GetTextureBitsPerUnit(DXGI_FORMAT format) {
        // List generated from <dxgiformat.h>
        // https://docs.microsoft.com/en-us/windows/win32/api/dxgiformat/ne-dxgiformat-dxgi_format
        switch (format) {
            case DXGI_FORMAT_R32G32B32A32_TYPELESS:
            case DXGI_FORMAT_R32G32B32A32_FLOAT:
            case DXGI_FORMAT_R32G32B32A32_UINT:
            case DXGI_FORMAT_R32G32B32A32_SINT:
                return 128;

            case DXGI_FORMAT_R32G32B32_TYPELESS:
            case DXGI_FORMAT_R32G32B32_FLOAT:
            case DXGI_FORMAT_R32G32B32_UINT:
            case DXGI_FORMAT_R32G32B32_SINT:
                return 96;

            case DXGI_FORMAT_R16G16B16A16_TYPELESS:
            case DXGI_FORMAT_R16G16B16A16_FLOAT:
            case DXGI_FORMAT_R16G16B16A16_UNORM:
            case DXGI_FORMAT_R16G16B16A16_UINT:
            case DXGI_FORMAT_R16G16B16A16_SNORM:
            case DXGI_FORMAT_R16G16B16A16_SINT:
                return 64;

            case DXGI_FORMAT_R32G32_TYPELESS:
            case DXGI_FORMAT_R32G32_FLOAT:
            case DXGI_FORMAT_R32G32_UINT:
            case DXGI_FORMAT_R32G32_SINT:
                return 64;

            case DXGI_FORMAT_R32G8X24_TYPELESS:
            case DXGI_FORMAT_D32_FLOAT_S8X24_UINT:
            case DXGI_FORMAT_R32_FLOAT_X8X24_TYPELESS:
            case DXGI_FORMAT_X32_TYPELESS_G8X24_UINT:
                return 64;

            case DXGI_FORMAT_R10G10B10A2_TYPELESS:
            case DXGI_FORMAT_R10G10B10A2_UNORM:
            case DXGI_FORMAT_R10G10B10A2_UINT:
            case DXGI_FORMAT_R11G11B10_FLOAT:
                return 32;

            case DXGI_FORMAT_R8G8B8A8_TYPELESS:
            case DXGI_FORMAT_R8G8B8A8_UNORM:
            case DXGI_FORMAT_R8G8B8A8_UNORM_SRGB:
            case DXGI_FORMAT_R8G8B8A8_UINT:
            case DXGI_FORMAT_R8G8B8A8_SNORM:
            case DXGI_FORMAT_R8G8B8A8_SINT:
                return 32;

            case DXGI_FORMAT_R16G16_TYPELESS:
            case DXGI_FORMAT_R16G16_FLOAT:
            case DXGI_FORMAT_R16G16_UNORM:
            case DXGI_FORMAT_R16G16_UINT:
            case DXGI_FORMAT_R16G16_SNORM:
            case DXGI_FORMAT_R16G16_SINT:
                return 32;

            case DXGI_FORMAT_R32_TYPELESS:
            case DXGI_FORMAT_D32_FLOAT:
            case DXGI_FORMAT_R32_FLOAT:
            case DXGI_FORMAT_R32_UINT:
            case DXGI_FORMAT_R32_SINT:
                return 32;

            case DXGI_FORMAT_R24G8_TYPELESS:
            case DXGI_FORMAT_D24_UNORM_S8_UINT:
            case DXGI_FORMAT_R24_UNORM_X8_TYPELESS:
            case DXGI_FORMAT_X24_TYPELESS_G8_UINT:
                return 32;

            case DXGI_FORMAT_R8G8_TYPELESS:
            case DXGI_FORMAT_R8G8_UNORM:
            case DXGI_FORMAT_R8G8_UINT:
            case DXGI_FORMAT_R8G8_SNORM:
            case DXGI_FORMAT_R8G8_SINT:
                return 16;

            case DXGI_FORMAT_R16_TYPELESS:
            case DXGI_FORMAT_R16_FLOAT:
            case DXGI_FORMAT_D16_UNORM:
            case DXGI_FORMAT_R16_UNORM:
            case DXGI_FORMAT_R16_UINT:
            case DXGI_FORMAT_R16_SNORM:
            case DXGI_FORMAT_R16_SINT:
                return 16;

            case DXGI_FORMAT_R8_TYPELESS:
            case DXGI_FORMAT_R8_UNORM:
            case DXGI_FORMAT_R8_UINT:
            case DXGI_FORMAT_R8_SNORM:
            case DXGI_FORMAT_R8_SINT:
                return 8;

            case DXGI_FORMAT_A8_UNORM:
                return 8;

            case DXGI_FORMAT_R1_UNORM:
                return 1;

            case DXGI_FORMAT_R9G9B9E5_SHAREDEXP:
            case DXGI_FORMAT_R8G8_B8G8_UNORM:
            case DXGI_FORMAT_G8R8_G8B8_UNORM:
                return 32;

            case DXGI_FORMAT_BC1_TYPELESS:
            case DXGI_FORMAT_BC1_UNORM:
            case DXGI_FORMAT_BC1_UNORM_SRGB:
                return 4;

            case DXGI_FORMAT_BC2_TYPELESS:
            case DXGI_FORMAT_BC2_UNORM:
            case DXGI_FORMAT_BC2_UNORM_SRGB:
                return 8;

            case DXGI_FORMAT_BC3_TYPELESS:
            case DXGI_FORMAT_BC3_UNORM:
            case DXGI_FORMAT_BC3_UNORM_SRGB:
                return 8;

            case DXGI_FORMAT_BC4_TYPELESS:
            case DXGI_FORMAT_BC4_UNORM:
            case DXGI_FORMAT_BC4_SNORM:
                return 4;

            case DXGI_FORMAT_BC5_TYPELESS:
            case DXGI_FORMAT_BC5_UNORM:
            case DXGI_FORMAT_BC5_SNORM:
                return 8;

            case DXGI_FORMAT_B5G6R5_UNORM:
            case DXGI_FORMAT_B5G5R5A1_UNORM:
                return 16;

            case DXGI_FORMAT_B8G8R8A8_UNORM:
            case DXGI_FORMAT_B8G8R8X8_UNORM:
            case DXGI_FORMAT_R10G10B10_XR_BIAS_A2_UNORM:
            case DXGI_FORMAT_B8G8R8A8_TYPELESS:
            case DXGI_FORMAT_B8G8R8A8_UNORM_SRGB:
            case DXGI_FORMAT_B8G8R8X8_TYPELESS:
            case DXGI_FORMAT_B8G8R8X8_UNORM_SRGB:
                return 32;

            case DXGI_FORMAT_BC6H_TYPELESS:
            case DXGI_FORMAT_BC6H_UF16:
            case DXGI_FORMAT_BC6H_SF16:
                return 8;

            case DXGI_FORMAT_BC7_TYPELESS:
            case DXGI_FORMAT_BC7_UNORM:
            case DXGI_FORMAT_BC7_UNORM_SRGB:
                return 8;

            case DXGI_FORMAT_NV12:
                return 12;

            default:
                return 0;
        }
    }

    bool IsTileZeroSized(const D3D12_TILE_SHAPE& tile) {
        return tile.HeightInTexels == 0 && tile.WidthInTexels == 0 && tile.DepthInTexels == 0;
    }

    bool IsBlockCompressionFormat(DXGI_FORMAT format) {
        // BC1 through BC7 are defined by two enum ranges in DXGIFormat.h.
        return (format >= DXGI_FORMAT_BC1_TYPELESS && format <= DXGI_FORMAT_BC5_SNORM) ||
               (format >= DXGI_FORMAT_BC6H_TYPELESS && format <= DXGI_FORMAT_BC7_UNORM_SRGB);
    }

    // Returns a "small" (or 4KB) tile for a given texture.
    D3D12_TILE_SHAPE GetSmallTextureTile(DXGI_FORMAT format,
                                         D3D12_RESOURCE_DIMENSION resourceDimension,
                                         uint32_t sampleCount) {
        // Tile size is determined by the bit depth of the texture used.
        //
        // For example, RGBA8 has a bit depth of 32 bits (8 bits per channel x 4 channels per
        // texel).
        //
        // 4KB tile = WxHxD x 4B/texel, D=1
        //          = H^2 x 4B/texel
        //          = 1024 x 4B/texel
        //          = 32x32x1 tile
        //
        const uint32_t bitsPerUnit = GetTextureBitsPerUnit(format);
        if (bitsPerUnit == 0) {
            return {};
        }

        D3D12_TILE_SHAPE tile = {};
        switch (resourceDimension) {
            case D3D12_RESOURCE_DIMENSION_TEXTURE1D: {
                // 1D textures/buffers always have a height and depth demension equal to 1.
                tile.HeightInTexels = 1;
                tile.DepthInTexels = 1;
                tile.WidthInTexels = (D3D12_SMALL_RESOURCE_PLACEMENT_ALIGNMENT * 8) / bitsPerUnit;

            } break;

            case D3D12_RESOURCE_DIMENSION_TEXTURE2D: {
                // 2D textures always have a depth demension equal to 1.
                tile.DepthInTexels = 1;

                // MemoryBlock compression means the returned texel dimensions are to be a multiple
                // of 4 (since the implementation compresses 4x4 blocks of texels).
                if (IsBlockCompressionFormat(format)) {
                    return {};  // TODO
                }

                // Tile size depends on number of bits per texel (or WxHx1 x bytes/texel).
                switch (bitsPerUnit) {
                    // 64x64x1 x 1 bytes per texel.
                    case 8: {
                        tile.WidthInTexels = 64;
                        tile.HeightInTexels = 64;
                    } break;

                    // 64x32x1 x 2 bytes per texel.
                    case 16: {
                        tile.WidthInTexels = 64;
                        tile.HeightInTexels = 32;
                    } break;

                    // 32x32x1 x 4 bytes per texel.
                    case 32: {
                        tile.WidthInTexels = 32;
                        tile.HeightInTexels = 32;
                    } break;

                    // 32x16x1 x 8 bytes per texel.
                    case 64: {
                        tile.WidthInTexels = 32;
                        tile.HeightInTexels = 16;
                    } break;

                    // 16x16x1 x 16 bytes per texel.
                    case 128: {
                        tile.WidthInTexels = 16;
                        tile.HeightInTexels = 16;
                    } break;

                    default:
                        tile = {};
                        break;
                }

                // Multi sampling means the returned texel demensions are a multiple of the number
                // of samples (or samples x byte per texel).
                switch (sampleCount) {
                    // 1x = 1x1 per texel = WxH bytes per texel (no change).
                    case 1: {
                    } break;

                    // 2x = 2x1 per texel = W/2 x H bytes per texel.
                    case 2: {
                        tile.WidthInTexels /= 2;
                        tile.HeightInTexels /= 1;
                    } break;

                    // 4x = 2x2 per texel = W/2 x H/2 bytes per texel.
                    case 4: {
                        tile.WidthInTexels /= 2;
                        tile.HeightInTexels /= 2;
                    } break;

                    // 8x = 4x2 per texel = W/4 x H/2 bytes per texel.
                    case 8: {
                        tile.WidthInTexels /= 4;
                        tile.HeightInTexels /= 2;
                    } break;

                    // 16x = 4x4 per texel = W/4 x H/4 bytes per texel.
                    case 16: {
                        tile.WidthInTexels /= 4;
                        tile.HeightInTexels /= 4;
                    } break;

                    default:
                        tile = {};
                        break;
                }

            } break;

            case D3D12_RESOURCE_DIMENSION_TEXTURE3D: {
                // WxHxD x bytes/texel.
                switch (bitsPerUnit) {
                    // 16x16x16 x 1 bytes per texel
                    case 8: {
                        tile.WidthInTexels = 16;
                        tile.HeightInTexels = 16;
                        tile.DepthInTexels = 16;
                    } break;

                    // 16x16x8 x 2 bytes per texel
                    case 16: {
                        tile.WidthInTexels = 16;
                        tile.HeightInTexels = 16;
                        tile.DepthInTexels = 8;
                    } break;

                    // 16x8x8 x 4 bytes per texel
                    case 32: {
                        tile.WidthInTexels = 16;
                        tile.HeightInTexels = 8;
                        tile.DepthInTexels = 8;
                    } break;

                    // 8x8x8 x 8 bytes per texel
                    case 64: {
                        tile.WidthInTexels = 8;
                        tile.HeightInTexels = 8;
                        tile.DepthInTexels = 8;
                    } break;

                    // 8x8x4 x 16 bytes per texel
                    case 128: {
                        tile.WidthInTexels = 8;
                        tile.HeightInTexels = 8;
                        tile.DepthInTexels = 4;
                    } break;

                    default:
                        tile = {};
                        break;
                }
            } break;

            default:
                break;
        }

        return tile;
    }

    bool IsAllowedToUseSmallAlignment(const D3D12_RESOURCE_DESC& resourceDescriptor) {
        // Per MSFT, no hardware supports multiplanar depth or video.
        if (IsMultiPlanarFormat(resourceDescriptor.Format)) {
            return false;
        }

        // Small alignment is only possible if the resource, of size equal to the larger alignment
        // (ex. 64KB), can be divided into small "tiles", a number equal to or greater than the size
        // equal to the smaller alignment (ex. 4KB).
        const D3D12_TILE_SHAPE& tile =
            GetSmallTextureTile(resourceDescriptor.Format, resourceDescriptor.Dimension,
                                resourceDescriptor.SampleDesc.Count);
        if (IsTileZeroSized(tile)) {
            return false;
        }

        return GetTileCount(resourceDescriptor, tile) <= 16;
    }

    HRESULT SetDebugObjectName(ID3D12Object* object, const std::string& name) {
        if (object == nullptr) {
            return E_POINTER;
        }
        if (name.empty()) {
            return S_FALSE;
        }
        return object->SetName(TCharToWString(name.c_str()).c_str());
    }

}  // namespace gpgmm::d3d12
