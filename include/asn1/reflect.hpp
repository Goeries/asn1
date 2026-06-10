// asn1/reflect.hpp — aggregate member reflection ("PFR technique") for C++23.
//
// member_count<T>: number of members of an aggregate, found by probing
// aggregate-initializability with N copies of a universally-convertible type.
// tie_members(t): destructures an aggregate into a std::tuple of references
// via structured bindings (one generated case per arity, up to max_members).
//
// Limits: plain aggregates only — no base classes, no bit-field members,
// no raw C-array members (std::array is fine). See README.
#pragma once

#include <cstddef>
#include <tuple>
#include <type_traits>
#include <utility>

namespace asn1::reflect {

inline constexpr std::size_t max_members = 64;

namespace detail {

// The conversion operator is never defined: it is only named in unevaluated
// contexts. Clang still eagerly instantiates constexpr constructor bodies it
// appears in and warns about the missing definition.
#if defined(__clang__)
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wundefined-inline"
#endif
struct universal_init {
    template<class T>
    constexpr operator T() const noexcept;
};
#if defined(__clang__)
#pragma clang diagnostic pop
#endif

template<class T, std::size_t N>
inline constexpr bool initializable_with_n = []<std::size_t... I>(std::index_sequence<I...>) {
    return requires { T{((void)I, universal_init{})...}; };
}(std::make_index_sequence<N>{});

template<class T, std::size_t N = 0>
constexpr std::size_t count_members_impl() {
    // NOLINTNEXTLINE(bugprone-branch-clone) -- same value, distinct meanings
    if constexpr (N > max_members) {
        return N; // sentinel: more members than we can destructure
    } else if constexpr (!initializable_with_n<T, N + 1>) {
        return N;
    } else {
        return count_members_impl<T, N + 1>();
    }
}

} // namespace detail

template<class T>
inline constexpr std::size_t member_count = detail::count_members_impl<std::remove_cvref_t<T>>();

template<class T>
inline constexpr bool is_std_array = false;
template<class T, std::size_t N>
inline constexpr bool is_std_array<std::array<T, N>> = true;

// An aggregate we can automatically map to/from an ASN.1 SEQUENCE.
template<class T>
concept reflectable = std::is_class_v<T> && std::is_aggregate_v<T> && !is_std_array<std::remove_cvref_t<T>> &&
                      std::is_default_constructible_v<T> && member_count<T> <= max_members;

template<class T>
    requires std::is_aggregate_v<std::remove_cvref_t<T>>
constexpr auto tie_members(T & t) noexcept {
    constexpr std::size_t n = member_count<T>;
    static_assert(n <= max_members, "asn1::reflect: aggregate has more members than max_members; "
                                    "specialize asn1::codec_traits for this type instead");
    if constexpr (n == 0) {
        return std::tuple<>{};
    } else if constexpr (n == 1) {
        auto & [m1] = t;
        return std::tie(m1);
    } else if constexpr (n == 2) {
        auto & [m1, m2] = t;
        return std::tie(m1, m2);
    } else if constexpr (n == 3) {
        auto & [m1, m2, m3] = t;
        return std::tie(m1, m2, m3);
    } else if constexpr (n == 4) {
        auto & [m1, m2, m3, m4] = t;
        return std::tie(m1, m2, m3, m4);
    } else if constexpr (n == 5) {
        auto & [m1, m2, m3, m4, m5] = t;
        return std::tie(m1, m2, m3, m4, m5);
    } else if constexpr (n == 6) {
        auto & [m1, m2, m3, m4, m5, m6] = t;
        return std::tie(m1, m2, m3, m4, m5, m6);
    } else if constexpr (n == 7) {
        auto & [m1, m2, m3, m4, m5, m6, m7] = t;
        return std::tie(m1, m2, m3, m4, m5, m6, m7);
    } else if constexpr (n == 8) {
        auto & [m1, m2, m3, m4, m5, m6, m7, m8] = t;
        return std::tie(m1, m2, m3, m4, m5, m6, m7, m8);
    } else if constexpr (n == 9) {
        auto & [m1, m2, m3, m4, m5, m6, m7, m8, m9] = t;
        return std::tie(m1, m2, m3, m4, m5, m6, m7, m8, m9);
    } else if constexpr (n == 10) {
        auto & [m1, m2, m3, m4, m5, m6, m7, m8, m9, m10] = t;
        return std::tie(m1, m2, m3, m4, m5, m6, m7, m8, m9, m10);
    } else if constexpr (n == 11) {
        auto & [m1, m2, m3, m4, m5, m6, m7, m8, m9, m10, m11] = t;
        return std::tie(m1, m2, m3, m4, m5, m6, m7, m8, m9, m10, m11);
    } else if constexpr (n == 12) {
        auto & [m1, m2, m3, m4, m5, m6, m7, m8, m9, m10, m11, m12] = t;
        return std::tie(m1, m2, m3, m4, m5, m6, m7, m8, m9, m10, m11, m12);
    } else if constexpr (n == 13) {
        auto & [m1, m2, m3, m4, m5, m6, m7, m8, m9, m10, m11, m12, m13] = t;
        return std::tie(m1, m2, m3, m4, m5, m6, m7, m8, m9, m10, m11, m12, m13);
    } else if constexpr (n == 14) {
        auto & [m1, m2, m3, m4, m5, m6, m7, m8, m9, m10, m11, m12, m13, m14] = t;
        return std::tie(m1, m2, m3, m4, m5, m6, m7, m8, m9, m10, m11, m12, m13, m14);
    } else if constexpr (n == 15) {
        auto & [m1, m2, m3, m4, m5, m6, m7, m8, m9, m10, m11, m12, m13, m14, m15] = t;
        return std::tie(m1, m2, m3, m4, m5, m6, m7, m8, m9, m10, m11, m12, m13, m14, m15);
    } else if constexpr (n == 16) {
        auto & [m1, m2, m3, m4, m5, m6, m7, m8, m9, m10, m11, m12, m13, m14, m15, m16] = t;
        return std::tie(m1, m2, m3, m4, m5, m6, m7, m8, m9, m10, m11, m12, m13, m14, m15, m16);
    } else if constexpr (n == 17) {
        auto & [m1, m2, m3, m4, m5, m6, m7, m8, m9, m10, m11, m12, m13, m14, m15, m16, m17] = t;
        return std::tie(m1, m2, m3, m4, m5, m6, m7, m8, m9, m10, m11, m12, m13, m14, m15, m16, m17);
    } else if constexpr (n == 18) {
        auto & [m1, m2, m3, m4, m5, m6, m7, m8, m9, m10, m11, m12, m13, m14, m15, m16, m17, m18] = t;
        return std::tie(m1, m2, m3, m4, m5, m6, m7, m8, m9, m10, m11, m12, m13, m14, m15, m16, m17, m18);
    } else if constexpr (n == 19) {
        auto & [m1, m2, m3, m4, m5, m6, m7, m8, m9, m10, m11, m12, m13, m14, m15, m16, m17, m18, m19] = t;
        return std::tie(m1, m2, m3, m4, m5, m6, m7, m8, m9, m10, m11, m12, m13, m14, m15, m16, m17, m18, m19);
    } else if constexpr (n == 20) {
        auto & [m1, m2, m3, m4, m5, m6, m7, m8, m9, m10, m11, m12, m13, m14, m15, m16, m17, m18, m19, m20] = t;
        return std::tie(m1, m2, m3, m4, m5, m6, m7, m8, m9, m10, m11, m12, m13, m14, m15, m16, m17, m18, m19, m20);
    } else if constexpr (n == 21) {
        auto & [m1, m2, m3, m4, m5, m6, m7, m8, m9, m10, m11, m12, m13, m14, m15, m16, m17, m18, m19, m20, m21] = t;
        return std::tie(m1, m2, m3, m4, m5, m6, m7, m8, m9, m10, m11, m12, m13, m14, m15, m16, m17, m18, m19, m20, m21);
    } else if constexpr (n == 22) {
        auto & [m1, m2, m3, m4, m5, m6, m7, m8, m9, m10, m11, m12, m13, m14, m15, m16, m17, m18, m19, m20, m21, m22] =
            t;
        return std::tie(m1, m2, m3, m4, m5, m6, m7, m8, m9, m10, m11, m12, m13, m14, m15, m16, m17, m18, m19, m20, m21,
                        m22);
    } else if constexpr (n == 23) {
        auto & [m1, m2, m3, m4, m5, m6, m7, m8, m9, m10, m11, m12, m13, m14, m15, m16, m17, m18, m19, m20, m21, m22,
                m23] = t;
        return std::tie(m1, m2, m3, m4, m5, m6, m7, m8, m9, m10, m11, m12, m13, m14, m15, m16, m17, m18, m19, m20, m21,
                        m22, m23);
    } else if constexpr (n == 24) {
        auto & [m1, m2, m3, m4, m5, m6, m7, m8, m9, m10, m11, m12, m13, m14, m15, m16, m17, m18, m19, m20, m21, m22,
                m23, m24] = t;
        return std::tie(m1, m2, m3, m4, m5, m6, m7, m8, m9, m10, m11, m12, m13, m14, m15, m16, m17, m18, m19, m20, m21,
                        m22, m23, m24);
    } else if constexpr (n == 25) {
        auto & [m1, m2, m3, m4, m5, m6, m7, m8, m9, m10, m11, m12, m13, m14, m15, m16, m17, m18, m19, m20, m21, m22,
                m23, m24, m25] = t;
        return std::tie(m1, m2, m3, m4, m5, m6, m7, m8, m9, m10, m11, m12, m13, m14, m15, m16, m17, m18, m19, m20, m21,
                        m22, m23, m24, m25);
    } else if constexpr (n == 26) {
        auto & [m1, m2, m3, m4, m5, m6, m7, m8, m9, m10, m11, m12, m13, m14, m15, m16, m17, m18, m19, m20, m21, m22,
                m23, m24, m25, m26] = t;
        return std::tie(m1, m2, m3, m4, m5, m6, m7, m8, m9, m10, m11, m12, m13, m14, m15, m16, m17, m18, m19, m20, m21,
                        m22, m23, m24, m25, m26);
    } else if constexpr (n == 27) {
        auto & [m1, m2, m3, m4, m5, m6, m7, m8, m9, m10, m11, m12, m13, m14, m15, m16, m17, m18, m19, m20, m21, m22,
                m23, m24, m25, m26, m27] = t;
        return std::tie(m1, m2, m3, m4, m5, m6, m7, m8, m9, m10, m11, m12, m13, m14, m15, m16, m17, m18, m19, m20, m21,
                        m22, m23, m24, m25, m26, m27);
    } else if constexpr (n == 28) {
        auto & [m1, m2, m3, m4, m5, m6, m7, m8, m9, m10, m11, m12, m13, m14, m15, m16, m17, m18, m19, m20, m21, m22,
                m23, m24, m25, m26, m27, m28] = t;
        return std::tie(m1, m2, m3, m4, m5, m6, m7, m8, m9, m10, m11, m12, m13, m14, m15, m16, m17, m18, m19, m20, m21,
                        m22, m23, m24, m25, m26, m27, m28);
    } else if constexpr (n == 29) {
        auto & [m1, m2, m3, m4, m5, m6, m7, m8, m9, m10, m11, m12, m13, m14, m15, m16, m17, m18, m19, m20, m21, m22,
                m23, m24, m25, m26, m27, m28, m29] = t;
        return std::tie(m1, m2, m3, m4, m5, m6, m7, m8, m9, m10, m11, m12, m13, m14, m15, m16, m17, m18, m19, m20, m21,
                        m22, m23, m24, m25, m26, m27, m28, m29);
    } else if constexpr (n == 30) {
        auto & [m1, m2, m3, m4, m5, m6, m7, m8, m9, m10, m11, m12, m13, m14, m15, m16, m17, m18, m19, m20, m21, m22,
                m23, m24, m25, m26, m27, m28, m29, m30] = t;
        return std::tie(m1, m2, m3, m4, m5, m6, m7, m8, m9, m10, m11, m12, m13, m14, m15, m16, m17, m18, m19, m20, m21,
                        m22, m23, m24, m25, m26, m27, m28, m29, m30);
    } else if constexpr (n == 31) {
        auto & [m1, m2, m3, m4, m5, m6, m7, m8, m9, m10, m11, m12, m13, m14, m15, m16, m17, m18, m19, m20, m21, m22,
                m23, m24, m25, m26, m27, m28, m29, m30, m31] = t;
        return std::tie(m1, m2, m3, m4, m5, m6, m7, m8, m9, m10, m11, m12, m13, m14, m15, m16, m17, m18, m19, m20, m21,
                        m22, m23, m24, m25, m26, m27, m28, m29, m30, m31);
    } else if constexpr (n == 32) {
        auto & [m1, m2, m3, m4, m5, m6, m7, m8, m9, m10, m11, m12, m13, m14, m15, m16, m17, m18, m19, m20, m21, m22,
                m23, m24, m25, m26, m27, m28, m29, m30, m31, m32] = t;
        return std::tie(m1, m2, m3, m4, m5, m6, m7, m8, m9, m10, m11, m12, m13, m14, m15, m16, m17, m18, m19, m20, m21,
                        m22, m23, m24, m25, m26, m27, m28, m29, m30, m31, m32);
    } else if constexpr (n == 33) {
        auto & [m1, m2, m3, m4, m5, m6, m7, m8, m9, m10, m11, m12, m13, m14, m15, m16, m17, m18, m19, m20, m21, m22,
                m23, m24, m25, m26, m27, m28, m29, m30, m31, m32, m33] = t;
        return std::tie(m1, m2, m3, m4, m5, m6, m7, m8, m9, m10, m11, m12, m13, m14, m15, m16, m17, m18, m19, m20, m21,
                        m22, m23, m24, m25, m26, m27, m28, m29, m30, m31, m32, m33);
    } else if constexpr (n == 34) {
        auto & [m1, m2, m3, m4, m5, m6, m7, m8, m9, m10, m11, m12, m13, m14, m15, m16, m17, m18, m19, m20, m21, m22,
                m23, m24, m25, m26, m27, m28, m29, m30, m31, m32, m33, m34] = t;
        return std::tie(m1, m2, m3, m4, m5, m6, m7, m8, m9, m10, m11, m12, m13, m14, m15, m16, m17, m18, m19, m20, m21,
                        m22, m23, m24, m25, m26, m27, m28, m29, m30, m31, m32, m33, m34);
    } else if constexpr (n == 35) {
        auto & [m1, m2, m3, m4, m5, m6, m7, m8, m9, m10, m11, m12, m13, m14, m15, m16, m17, m18, m19, m20, m21, m22,
                m23, m24, m25, m26, m27, m28, m29, m30, m31, m32, m33, m34, m35] = t;
        return std::tie(m1, m2, m3, m4, m5, m6, m7, m8, m9, m10, m11, m12, m13, m14, m15, m16, m17, m18, m19, m20, m21,
                        m22, m23, m24, m25, m26, m27, m28, m29, m30, m31, m32, m33, m34, m35);
    } else if constexpr (n == 36) {
        auto & [m1, m2, m3, m4, m5, m6, m7, m8, m9, m10, m11, m12, m13, m14, m15, m16, m17, m18, m19, m20, m21, m22,
                m23, m24, m25, m26, m27, m28, m29, m30, m31, m32, m33, m34, m35, m36] = t;
        return std::tie(m1, m2, m3, m4, m5, m6, m7, m8, m9, m10, m11, m12, m13, m14, m15, m16, m17, m18, m19, m20, m21,
                        m22, m23, m24, m25, m26, m27, m28, m29, m30, m31, m32, m33, m34, m35, m36);
    } else if constexpr (n == 37) {
        auto & [m1, m2, m3, m4, m5, m6, m7, m8, m9, m10, m11, m12, m13, m14, m15, m16, m17, m18, m19, m20, m21, m22,
                m23, m24, m25, m26, m27, m28, m29, m30, m31, m32, m33, m34, m35, m36, m37] = t;
        return std::tie(m1, m2, m3, m4, m5, m6, m7, m8, m9, m10, m11, m12, m13, m14, m15, m16, m17, m18, m19, m20, m21,
                        m22, m23, m24, m25, m26, m27, m28, m29, m30, m31, m32, m33, m34, m35, m36, m37);
    } else if constexpr (n == 38) {
        auto & [m1, m2, m3, m4, m5, m6, m7, m8, m9, m10, m11, m12, m13, m14, m15, m16, m17, m18, m19, m20, m21, m22,
                m23, m24, m25, m26, m27, m28, m29, m30, m31, m32, m33, m34, m35, m36, m37, m38] = t;
        return std::tie(m1, m2, m3, m4, m5, m6, m7, m8, m9, m10, m11, m12, m13, m14, m15, m16, m17, m18, m19, m20, m21,
                        m22, m23, m24, m25, m26, m27, m28, m29, m30, m31, m32, m33, m34, m35, m36, m37, m38);
    } else if constexpr (n == 39) {
        auto & [m1, m2, m3, m4, m5, m6, m7, m8, m9, m10, m11, m12, m13, m14, m15, m16, m17, m18, m19, m20, m21, m22,
                m23, m24, m25, m26, m27, m28, m29, m30, m31, m32, m33, m34, m35, m36, m37, m38, m39] = t;
        return std::tie(m1, m2, m3, m4, m5, m6, m7, m8, m9, m10, m11, m12, m13, m14, m15, m16, m17, m18, m19, m20, m21,
                        m22, m23, m24, m25, m26, m27, m28, m29, m30, m31, m32, m33, m34, m35, m36, m37, m38, m39);
    } else if constexpr (n == 40) {
        auto & [m1, m2, m3, m4, m5, m6, m7, m8, m9, m10, m11, m12, m13, m14, m15, m16, m17, m18, m19, m20, m21, m22,
                m23, m24, m25, m26, m27, m28, m29, m30, m31, m32, m33, m34, m35, m36, m37, m38, m39, m40] = t;
        return std::tie(m1, m2, m3, m4, m5, m6, m7, m8, m9, m10, m11, m12, m13, m14, m15, m16, m17, m18, m19, m20, m21,
                        m22, m23, m24, m25, m26, m27, m28, m29, m30, m31, m32, m33, m34, m35, m36, m37, m38, m39, m40);
    } else if constexpr (n == 41) {
        auto & [m1, m2, m3, m4, m5, m6, m7, m8, m9, m10, m11, m12, m13, m14, m15, m16, m17, m18, m19, m20, m21, m22,
                m23, m24, m25, m26, m27, m28, m29, m30, m31, m32, m33, m34, m35, m36, m37, m38, m39, m40, m41] = t;
        return std::tie(m1, m2, m3, m4, m5, m6, m7, m8, m9, m10, m11, m12, m13, m14, m15, m16, m17, m18, m19, m20, m21,
                        m22, m23, m24, m25, m26, m27, m28, m29, m30, m31, m32, m33, m34, m35, m36, m37, m38, m39, m40,
                        m41);
    } else if constexpr (n == 42) {
        auto & [m1, m2, m3, m4, m5, m6, m7, m8, m9, m10, m11, m12, m13, m14, m15, m16, m17, m18, m19, m20, m21, m22,
                m23, m24, m25, m26, m27, m28, m29, m30, m31, m32, m33, m34, m35, m36, m37, m38, m39, m40, m41, m42] = t;
        return std::tie(m1, m2, m3, m4, m5, m6, m7, m8, m9, m10, m11, m12, m13, m14, m15, m16, m17, m18, m19, m20, m21,
                        m22, m23, m24, m25, m26, m27, m28, m29, m30, m31, m32, m33, m34, m35, m36, m37, m38, m39, m40,
                        m41, m42);
    } else if constexpr (n == 43) {
        auto & [m1, m2, m3, m4, m5, m6, m7, m8, m9, m10, m11, m12, m13, m14, m15, m16, m17, m18, m19, m20, m21, m22,
                m23, m24, m25, m26, m27, m28, m29, m30, m31, m32, m33, m34, m35, m36, m37, m38, m39, m40, m41, m42,
                m43] = t;
        return std::tie(m1, m2, m3, m4, m5, m6, m7, m8, m9, m10, m11, m12, m13, m14, m15, m16, m17, m18, m19, m20, m21,
                        m22, m23, m24, m25, m26, m27, m28, m29, m30, m31, m32, m33, m34, m35, m36, m37, m38, m39, m40,
                        m41, m42, m43);
    } else if constexpr (n == 44) {
        auto & [m1, m2, m3, m4, m5, m6, m7, m8, m9, m10, m11, m12, m13, m14, m15, m16, m17, m18, m19, m20, m21, m22,
                m23, m24, m25, m26, m27, m28, m29, m30, m31, m32, m33, m34, m35, m36, m37, m38, m39, m40, m41, m42, m43,
                m44] = t;
        return std::tie(m1, m2, m3, m4, m5, m6, m7, m8, m9, m10, m11, m12, m13, m14, m15, m16, m17, m18, m19, m20, m21,
                        m22, m23, m24, m25, m26, m27, m28, m29, m30, m31, m32, m33, m34, m35, m36, m37, m38, m39, m40,
                        m41, m42, m43, m44);
    } else if constexpr (n == 45) {
        auto & [m1, m2, m3, m4, m5, m6, m7, m8, m9, m10, m11, m12, m13, m14, m15, m16, m17, m18, m19, m20, m21, m22,
                m23, m24, m25, m26, m27, m28, m29, m30, m31, m32, m33, m34, m35, m36, m37, m38, m39, m40, m41, m42, m43,
                m44, m45] = t;
        return std::tie(m1, m2, m3, m4, m5, m6, m7, m8, m9, m10, m11, m12, m13, m14, m15, m16, m17, m18, m19, m20, m21,
                        m22, m23, m24, m25, m26, m27, m28, m29, m30, m31, m32, m33, m34, m35, m36, m37, m38, m39, m40,
                        m41, m42, m43, m44, m45);
    } else if constexpr (n == 46) {
        auto & [m1, m2, m3, m4, m5, m6, m7, m8, m9, m10, m11, m12, m13, m14, m15, m16, m17, m18, m19, m20, m21, m22,
                m23, m24, m25, m26, m27, m28, m29, m30, m31, m32, m33, m34, m35, m36, m37, m38, m39, m40, m41, m42, m43,
                m44, m45, m46] = t;
        return std::tie(m1, m2, m3, m4, m5, m6, m7, m8, m9, m10, m11, m12, m13, m14, m15, m16, m17, m18, m19, m20, m21,
                        m22, m23, m24, m25, m26, m27, m28, m29, m30, m31, m32, m33, m34, m35, m36, m37, m38, m39, m40,
                        m41, m42, m43, m44, m45, m46);
    } else if constexpr (n == 47) {
        auto & [m1, m2, m3, m4, m5, m6, m7, m8, m9, m10, m11, m12, m13, m14, m15, m16, m17, m18, m19, m20, m21, m22,
                m23, m24, m25, m26, m27, m28, m29, m30, m31, m32, m33, m34, m35, m36, m37, m38, m39, m40, m41, m42, m43,
                m44, m45, m46, m47] = t;
        return std::tie(m1, m2, m3, m4, m5, m6, m7, m8, m9, m10, m11, m12, m13, m14, m15, m16, m17, m18, m19, m20, m21,
                        m22, m23, m24, m25, m26, m27, m28, m29, m30, m31, m32, m33, m34, m35, m36, m37, m38, m39, m40,
                        m41, m42, m43, m44, m45, m46, m47);
    } else if constexpr (n == 48) {
        auto & [m1, m2, m3, m4, m5, m6, m7, m8, m9, m10, m11, m12, m13, m14, m15, m16, m17, m18, m19, m20, m21, m22,
                m23, m24, m25, m26, m27, m28, m29, m30, m31, m32, m33, m34, m35, m36, m37, m38, m39, m40, m41, m42, m43,
                m44, m45, m46, m47, m48] = t;
        return std::tie(m1, m2, m3, m4, m5, m6, m7, m8, m9, m10, m11, m12, m13, m14, m15, m16, m17, m18, m19, m20, m21,
                        m22, m23, m24, m25, m26, m27, m28, m29, m30, m31, m32, m33, m34, m35, m36, m37, m38, m39, m40,
                        m41, m42, m43, m44, m45, m46, m47, m48);
    } else if constexpr (n == 49) {
        auto & [m1, m2, m3, m4, m5, m6, m7, m8, m9, m10, m11, m12, m13, m14, m15, m16, m17, m18, m19, m20, m21, m22,
                m23, m24, m25, m26, m27, m28, m29, m30, m31, m32, m33, m34, m35, m36, m37, m38, m39, m40, m41, m42, m43,
                m44, m45, m46, m47, m48, m49] = t;
        return std::tie(m1, m2, m3, m4, m5, m6, m7, m8, m9, m10, m11, m12, m13, m14, m15, m16, m17, m18, m19, m20, m21,
                        m22, m23, m24, m25, m26, m27, m28, m29, m30, m31, m32, m33, m34, m35, m36, m37, m38, m39, m40,
                        m41, m42, m43, m44, m45, m46, m47, m48, m49);
    } else if constexpr (n == 50) {
        auto & [m1, m2, m3, m4, m5, m6, m7, m8, m9, m10, m11, m12, m13, m14, m15, m16, m17, m18, m19, m20, m21, m22,
                m23, m24, m25, m26, m27, m28, m29, m30, m31, m32, m33, m34, m35, m36, m37, m38, m39, m40, m41, m42, m43,
                m44, m45, m46, m47, m48, m49, m50] = t;
        return std::tie(m1, m2, m3, m4, m5, m6, m7, m8, m9, m10, m11, m12, m13, m14, m15, m16, m17, m18, m19, m20, m21,
                        m22, m23, m24, m25, m26, m27, m28, m29, m30, m31, m32, m33, m34, m35, m36, m37, m38, m39, m40,
                        m41, m42, m43, m44, m45, m46, m47, m48, m49, m50);
    } else if constexpr (n == 51) {
        auto & [m1, m2, m3, m4, m5, m6, m7, m8, m9, m10, m11, m12, m13, m14, m15, m16, m17, m18, m19, m20, m21, m22,
                m23, m24, m25, m26, m27, m28, m29, m30, m31, m32, m33, m34, m35, m36, m37, m38, m39, m40, m41, m42, m43,
                m44, m45, m46, m47, m48, m49, m50, m51] = t;
        return std::tie(m1, m2, m3, m4, m5, m6, m7, m8, m9, m10, m11, m12, m13, m14, m15, m16, m17, m18, m19, m20, m21,
                        m22, m23, m24, m25, m26, m27, m28, m29, m30, m31, m32, m33, m34, m35, m36, m37, m38, m39, m40,
                        m41, m42, m43, m44, m45, m46, m47, m48, m49, m50, m51);
    } else if constexpr (n == 52) {
        auto & [m1, m2, m3, m4, m5, m6, m7, m8, m9, m10, m11, m12, m13, m14, m15, m16, m17, m18, m19, m20, m21, m22,
                m23, m24, m25, m26, m27, m28, m29, m30, m31, m32, m33, m34, m35, m36, m37, m38, m39, m40, m41, m42, m43,
                m44, m45, m46, m47, m48, m49, m50, m51, m52] = t;
        return std::tie(m1, m2, m3, m4, m5, m6, m7, m8, m9, m10, m11, m12, m13, m14, m15, m16, m17, m18, m19, m20, m21,
                        m22, m23, m24, m25, m26, m27, m28, m29, m30, m31, m32, m33, m34, m35, m36, m37, m38, m39, m40,
                        m41, m42, m43, m44, m45, m46, m47, m48, m49, m50, m51, m52);
    } else if constexpr (n == 53) {
        auto & [m1, m2, m3, m4, m5, m6, m7, m8, m9, m10, m11, m12, m13, m14, m15, m16, m17, m18, m19, m20, m21, m22,
                m23, m24, m25, m26, m27, m28, m29, m30, m31, m32, m33, m34, m35, m36, m37, m38, m39, m40, m41, m42, m43,
                m44, m45, m46, m47, m48, m49, m50, m51, m52, m53] = t;
        return std::tie(m1, m2, m3, m4, m5, m6, m7, m8, m9, m10, m11, m12, m13, m14, m15, m16, m17, m18, m19, m20, m21,
                        m22, m23, m24, m25, m26, m27, m28, m29, m30, m31, m32, m33, m34, m35, m36, m37, m38, m39, m40,
                        m41, m42, m43, m44, m45, m46, m47, m48, m49, m50, m51, m52, m53);
    } else if constexpr (n == 54) {
        auto & [m1, m2, m3, m4, m5, m6, m7, m8, m9, m10, m11, m12, m13, m14, m15, m16, m17, m18, m19, m20, m21, m22,
                m23, m24, m25, m26, m27, m28, m29, m30, m31, m32, m33, m34, m35, m36, m37, m38, m39, m40, m41, m42, m43,
                m44, m45, m46, m47, m48, m49, m50, m51, m52, m53, m54] = t;
        return std::tie(m1, m2, m3, m4, m5, m6, m7, m8, m9, m10, m11, m12, m13, m14, m15, m16, m17, m18, m19, m20, m21,
                        m22, m23, m24, m25, m26, m27, m28, m29, m30, m31, m32, m33, m34, m35, m36, m37, m38, m39, m40,
                        m41, m42, m43, m44, m45, m46, m47, m48, m49, m50, m51, m52, m53, m54);
    } else if constexpr (n == 55) {
        auto & [m1, m2, m3, m4, m5, m6, m7, m8, m9, m10, m11, m12, m13, m14, m15, m16, m17, m18, m19, m20, m21, m22,
                m23, m24, m25, m26, m27, m28, m29, m30, m31, m32, m33, m34, m35, m36, m37, m38, m39, m40, m41, m42, m43,
                m44, m45, m46, m47, m48, m49, m50, m51, m52, m53, m54, m55] = t;
        return std::tie(m1, m2, m3, m4, m5, m6, m7, m8, m9, m10, m11, m12, m13, m14, m15, m16, m17, m18, m19, m20, m21,
                        m22, m23, m24, m25, m26, m27, m28, m29, m30, m31, m32, m33, m34, m35, m36, m37, m38, m39, m40,
                        m41, m42, m43, m44, m45, m46, m47, m48, m49, m50, m51, m52, m53, m54, m55);
    } else if constexpr (n == 56) {
        auto & [m1, m2, m3, m4, m5, m6, m7, m8, m9, m10, m11, m12, m13, m14, m15, m16, m17, m18, m19, m20, m21, m22,
                m23, m24, m25, m26, m27, m28, m29, m30, m31, m32, m33, m34, m35, m36, m37, m38, m39, m40, m41, m42, m43,
                m44, m45, m46, m47, m48, m49, m50, m51, m52, m53, m54, m55, m56] = t;
        return std::tie(m1, m2, m3, m4, m5, m6, m7, m8, m9, m10, m11, m12, m13, m14, m15, m16, m17, m18, m19, m20, m21,
                        m22, m23, m24, m25, m26, m27, m28, m29, m30, m31, m32, m33, m34, m35, m36, m37, m38, m39, m40,
                        m41, m42, m43, m44, m45, m46, m47, m48, m49, m50, m51, m52, m53, m54, m55, m56);
    } else if constexpr (n == 57) {
        auto & [m1, m2, m3, m4, m5, m6, m7, m8, m9, m10, m11, m12, m13, m14, m15, m16, m17, m18, m19, m20, m21, m22,
                m23, m24, m25, m26, m27, m28, m29, m30, m31, m32, m33, m34, m35, m36, m37, m38, m39, m40, m41, m42, m43,
                m44, m45, m46, m47, m48, m49, m50, m51, m52, m53, m54, m55, m56, m57] = t;
        return std::tie(m1, m2, m3, m4, m5, m6, m7, m8, m9, m10, m11, m12, m13, m14, m15, m16, m17, m18, m19, m20, m21,
                        m22, m23, m24, m25, m26, m27, m28, m29, m30, m31, m32, m33, m34, m35, m36, m37, m38, m39, m40,
                        m41, m42, m43, m44, m45, m46, m47, m48, m49, m50, m51, m52, m53, m54, m55, m56, m57);
    } else if constexpr (n == 58) {
        auto & [m1, m2, m3, m4, m5, m6, m7, m8, m9, m10, m11, m12, m13, m14, m15, m16, m17, m18, m19, m20, m21, m22,
                m23, m24, m25, m26, m27, m28, m29, m30, m31, m32, m33, m34, m35, m36, m37, m38, m39, m40, m41, m42, m43,
                m44, m45, m46, m47, m48, m49, m50, m51, m52, m53, m54, m55, m56, m57, m58] = t;
        return std::tie(m1, m2, m3, m4, m5, m6, m7, m8, m9, m10, m11, m12, m13, m14, m15, m16, m17, m18, m19, m20, m21,
                        m22, m23, m24, m25, m26, m27, m28, m29, m30, m31, m32, m33, m34, m35, m36, m37, m38, m39, m40,
                        m41, m42, m43, m44, m45, m46, m47, m48, m49, m50, m51, m52, m53, m54, m55, m56, m57, m58);
    } else if constexpr (n == 59) {
        auto & [m1, m2, m3, m4, m5, m6, m7, m8, m9, m10, m11, m12, m13, m14, m15, m16, m17, m18, m19, m20, m21, m22,
                m23, m24, m25, m26, m27, m28, m29, m30, m31, m32, m33, m34, m35, m36, m37, m38, m39, m40, m41, m42, m43,
                m44, m45, m46, m47, m48, m49, m50, m51, m52, m53, m54, m55, m56, m57, m58, m59] = t;
        return std::tie(m1, m2, m3, m4, m5, m6, m7, m8, m9, m10, m11, m12, m13, m14, m15, m16, m17, m18, m19, m20, m21,
                        m22, m23, m24, m25, m26, m27, m28, m29, m30, m31, m32, m33, m34, m35, m36, m37, m38, m39, m40,
                        m41, m42, m43, m44, m45, m46, m47, m48, m49, m50, m51, m52, m53, m54, m55, m56, m57, m58, m59);
    } else if constexpr (n == 60) {
        auto & [m1, m2, m3, m4, m5, m6, m7, m8, m9, m10, m11, m12, m13, m14, m15, m16, m17, m18, m19, m20, m21, m22,
                m23, m24, m25, m26, m27, m28, m29, m30, m31, m32, m33, m34, m35, m36, m37, m38, m39, m40, m41, m42, m43,
                m44, m45, m46, m47, m48, m49, m50, m51, m52, m53, m54, m55, m56, m57, m58, m59, m60] = t;
        return std::tie(m1, m2, m3, m4, m5, m6, m7, m8, m9, m10, m11, m12, m13, m14, m15, m16, m17, m18, m19, m20, m21,
                        m22, m23, m24, m25, m26, m27, m28, m29, m30, m31, m32, m33, m34, m35, m36, m37, m38, m39, m40,
                        m41, m42, m43, m44, m45, m46, m47, m48, m49, m50, m51, m52, m53, m54, m55, m56, m57, m58, m59,
                        m60);
    } else if constexpr (n == 61) {
        auto & [m1, m2, m3, m4, m5, m6, m7, m8, m9, m10, m11, m12, m13, m14, m15, m16, m17, m18, m19, m20, m21, m22,
                m23, m24, m25, m26, m27, m28, m29, m30, m31, m32, m33, m34, m35, m36, m37, m38, m39, m40, m41, m42, m43,
                m44, m45, m46, m47, m48, m49, m50, m51, m52, m53, m54, m55, m56, m57, m58, m59, m60, m61] = t;
        return std::tie(m1, m2, m3, m4, m5, m6, m7, m8, m9, m10, m11, m12, m13, m14, m15, m16, m17, m18, m19, m20, m21,
                        m22, m23, m24, m25, m26, m27, m28, m29, m30, m31, m32, m33, m34, m35, m36, m37, m38, m39, m40,
                        m41, m42, m43, m44, m45, m46, m47, m48, m49, m50, m51, m52, m53, m54, m55, m56, m57, m58, m59,
                        m60, m61);
    } else if constexpr (n == 62) {
        auto & [m1, m2, m3, m4, m5, m6, m7, m8, m9, m10, m11, m12, m13, m14, m15, m16, m17, m18, m19, m20, m21, m22,
                m23, m24, m25, m26, m27, m28, m29, m30, m31, m32, m33, m34, m35, m36, m37, m38, m39, m40, m41, m42, m43,
                m44, m45, m46, m47, m48, m49, m50, m51, m52, m53, m54, m55, m56, m57, m58, m59, m60, m61, m62] = t;
        return std::tie(m1, m2, m3, m4, m5, m6, m7, m8, m9, m10, m11, m12, m13, m14, m15, m16, m17, m18, m19, m20, m21,
                        m22, m23, m24, m25, m26, m27, m28, m29, m30, m31, m32, m33, m34, m35, m36, m37, m38, m39, m40,
                        m41, m42, m43, m44, m45, m46, m47, m48, m49, m50, m51, m52, m53, m54, m55, m56, m57, m58, m59,
                        m60, m61, m62);
    } else if constexpr (n == 63) {
        auto & [m1, m2, m3, m4, m5, m6, m7, m8, m9, m10, m11, m12, m13, m14, m15, m16, m17, m18, m19, m20, m21, m22,
                m23, m24, m25, m26, m27, m28, m29, m30, m31, m32, m33, m34, m35, m36, m37, m38, m39, m40, m41, m42, m43,
                m44, m45, m46, m47, m48, m49, m50, m51, m52, m53, m54, m55, m56, m57, m58, m59, m60, m61, m62, m63] = t;
        return std::tie(m1, m2, m3, m4, m5, m6, m7, m8, m9, m10, m11, m12, m13, m14, m15, m16, m17, m18, m19, m20, m21,
                        m22, m23, m24, m25, m26, m27, m28, m29, m30, m31, m32, m33, m34, m35, m36, m37, m38, m39, m40,
                        m41, m42, m43, m44, m45, m46, m47, m48, m49, m50, m51, m52, m53, m54, m55, m56, m57, m58, m59,
                        m60, m61, m62, m63);
    } else if constexpr (n == 64) {
        auto & [m1, m2, m3, m4, m5, m6, m7, m8, m9, m10, m11, m12, m13, m14, m15, m16, m17, m18, m19, m20, m21, m22,
                m23, m24, m25, m26, m27, m28, m29, m30, m31, m32, m33, m34, m35, m36, m37, m38, m39, m40, m41, m42, m43,
                m44, m45, m46, m47, m48, m49, m50, m51, m52, m53, m54, m55, m56, m57, m58, m59, m60, m61, m62, m63,
                m64] = t;
        return std::tie(m1, m2, m3, m4, m5, m6, m7, m8, m9, m10, m11, m12, m13, m14, m15, m16, m17, m18, m19, m20, m21,
                        m22, m23, m24, m25, m26, m27, m28, m29, m30, m31, m32, m33, m34, m35, m36, m37, m38, m39, m40,
                        m41, m42, m43, m44, m45, m46, m47, m48, m49, m50, m51, m52, m53, m54, m55, m56, m57, m58, m59,
                        m60, m61, m62, m63, m64);
    }
}

} // namespace asn1::reflect
