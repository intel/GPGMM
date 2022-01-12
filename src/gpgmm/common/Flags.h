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

#ifndef GPGMM_COMMON_FLAGS_H_
#define GPGMM_COMMON_FLAGS_H_

namespace gpgmm {

    // Flags is a type-safe means of storing enum values that can be OR'd
    // together without requiring a cast.
    template <typename EnumT, typename ValueT = int>
    class Flags final {
      public:
        using enum_type = EnumT;
        using value_type = ValueT;

        constexpr Flags() : mValue(0) {
        }

        constexpr Flags(EnumT flag) : mValue(static_cast<ValueT>(flag)) {
        }

        constexpr explicit Flags(ValueT value) : mValue(static_cast<ValueT>(value)) {
        }

        constexpr bool operator==(EnumT flag) const {
            return mValue == static_cast<ValueT>(flag);
        }

        constexpr bool operator!=(EnumT flag) const {
            return mValue != static_cast<ValueT>(flag);
        }

        // Compound assignment between Flags.

        Flags& operator&=(const Flags& flags) {
            mValue &= flags.mValue;
            return *this;
        }

        Flags& operator|=(const Flags& flags) {
            mValue |= flags.mValue;
            return *this;
        }

        Flags& operator^=(const Flags& flags) {
            mValue ^= flags.mValue;
            return *this;
        }

        // Bitwise between Flags.

        constexpr Flags operator&(const Flags& flags) const {
            return Flags(mValue & flags.mValue);
        }

        constexpr Flags operator|(const Flags& flags) const {
            return Flags(mValue | flags.mValue);
        }

        constexpr Flags operator^(const Flags& flags) const {
            return Flags(mValue ^ flags.mValue);
        }

        // Bitwise using raw enum.

        constexpr Flags operator&(EnumT flag) const {
            return operator&(Flags(flag));
        }

        constexpr Flags operator|(EnumT flag) const {
            return operator|(Flags(flag));
        }

        constexpr Flags operator^(EnumT flag) const {
            return operator^(Flags(flag));
        }

        // Compound assignment using raw enum.

        Flags& operator&=(EnumT flag) {
            return operator&=(Flags(flag));
        }

        Flags& operator|=(EnumT flag) {
            return operator|=(Flags(flag));
        }

        Flags& operator^=(EnumT flag) {
            return operator^=(Flags(flag));
        }

        constexpr Flags operator~() const {
            return Flags(~mValue);
        }

        constexpr bool operator!() const {
            return !mValue;
        }

        operator bool() const {
            return mValue != 0;
        }

      private:
        ValueT mValue;
    };

// Overloaded operations are inline to avoid duplicate symbols from being
// generated and failing to link when using the macro across multiple cpps.
#define DEFINE_OPERATORS_FOR_FLAGS(Type)                                        \
    inline constexpr Type operator&(Type::enum_type lhs, Type::enum_type rhs) { \
        return Type(lhs) & rhs;                                                 \
    }                                                                           \
    inline constexpr Type operator&(Type::enum_type lhs, const Type& rhs) {     \
        return rhs & lhs;                                                       \
    }                                                                           \
    inline void operator&(Type::enum_type lhs, Type::value_type rhs) {          \
    }                                                                           \
    inline constexpr Type operator|(Type::enum_type lhs, Type::enum_type rhs) { \
        return Type(lhs) | rhs;                                                 \
    }                                                                           \
    inline constexpr Type operator|(Type::enum_type lhs, const Type& rhs) {     \
        return rhs | lhs;                                                       \
    }                                                                           \
    inline void operator|(Type::enum_type lhs, Type::value_type rhs) {          \
    }                                                                           \
    inline constexpr Type operator^(Type::enum_type lhs, Type::enum_type rhs) { \
        return Type(lhs) ^ rhs;                                                 \
    }                                                                           \
    inline constexpr Type operator^(Type::enum_type lhs, const Type& rhs) {     \
        return rhs ^ lhs;                                                       \
    }                                                                           \
    inline void operator^(Type::enum_type lhs, Type::value_type rhs) {          \
    }                                                                           \
    inline constexpr Type operator~(Type::enum_type val) {                      \
        return ~Type(val);                                                      \
    }

}  // namespace gpgmm

#endif  // GPGMM_COMMON_FLAGS_H_
