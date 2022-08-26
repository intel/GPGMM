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

#ifndef GPGMM_UTILS_ENUMFLAGS_H_
#define GPGMM_UTILS_ENUMFLAGS_H_

#include <cstdint>

namespace gpgmm {

    // Returns true if all flags of B are in A.
    template <typename EnumFlagsType1, typename EnumFlagsType2>
    bool HasAllFlags(const EnumFlagsType1& a, const EnumFlagsType2& b) {
        return (a & b) == b;
    }

// Define enum-operator overloads to enable bit-wise operations on enum types that are used to
// define flags. Use DEFINE_ENUM_FLAG_OPERATORS(MyType) to enable these operators for MyType.
#ifndef DEFINE_ENUM_FLAG_OPERATORS

    template <size_t SizeInBytes>
    struct EnumFlagTrait;

    template <>
    struct EnumFlagTrait<1> {
        typedef int8_t SizeType;
    };

    template <>
    struct EnumFlagTrait<2> {
        typedef int16_t SizeType;
    };

    template <>
    struct EnumFlagTrait<4> {
        typedef int32_t SizeType;
    };

    template <class EnumFlag>
    struct EnumFlagInteger {
        typedef typename EnumFlagTrait<sizeof(EnumFlag)>::SizeType SizeType;
    };

// Overloaded operations are inline to avoid duplicate symbols from being
// generated and failing to link when using the macro across multiple cpps.
#    define DEFINE_ENUM_FLAG_OPERATORS(EnumType)                                     \
        inline EnumType operator|(EnumType a, EnumType b) {                          \
            return EnumType((static_cast<EnumFlagInteger<EnumType>::SizeType>(a)) |  \
                            static_cast<EnumFlagInteger<EnumType>::SizeType>(b));    \
        }                                                                            \
        inline EnumType& operator|=(EnumType& a, EnumType b) {                       \
            return reinterpret_cast<EnumType&>(                                      \
                (reinterpret_cast<EnumFlagInteger<EnumType>::SizeType&>(a)) |=       \
                (static_cast<EnumFlagInteger<EnumType>::SizeType>(b)));              \
        }                                                                            \
        inline EnumType operator&(EnumType a, EnumType b) {                          \
            return EnumType((static_cast<EnumFlagInteger<EnumType>::SizeType>(a)) &  \
                            (static_cast<EnumFlagInteger<EnumType>::SizeType>(b)));  \
        }                                                                            \
        inline EnumType& operator&=(EnumType& a, EnumType b) {                       \
            return reinterpret_cast<EnumType&>(                                      \
                (reinterpret_cast<EnumFlagInteger<EnumType>::SizeType&>(a)) &=       \
                (static_cast<EnumFlagInteger<EnumType>::SizeType>(b)));              \
        }                                                                            \
        inline EnumType operator~(EnumType a) {                                      \
            return EnumType(~(static_cast<EnumFlagInteger<EnumType>::SizeType>(a))); \
        }                                                                            \
        inline EnumType operator^(EnumType a, EnumType b) {                          \
            return EnumType((static_cast<EnumFlagInteger<EnumType>::SizeType>(a)) ^  \
                            (static_cast<EnumFlagInteger<EnumType>::SizeType>(b)));  \
        }                                                                            \
        inline EnumType& operator^=(EnumType& a, EnumType b) {                       \
            return reinterpret_cast<EnumType&>(                                      \
                (reinterpret_cast<EnumFlagInteger<EnumType>::SizeType&>(a)) ^=       \
                (static_cast<EnumFlagInteger<EnumType>::SizeType>(b)));              \
        }

#endif  // DEFINE_ENUM_FLAG_OPERATORS

}  // namespace gpgmm

#endif  // GPGMM_UTILS_ENUMFLAGS_H_
