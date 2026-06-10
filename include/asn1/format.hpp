// asn1/format.hpp — std::formatter specializations for diagnostics:
// tag, error, oid, and a dumpasn1-style tree dump for asn1::value.
#pragma once

#include <format>
#include <string>
#include <string_view>

#include "core.hpp"
#include "types.hpp"
#include "value.hpp"

namespace asn1 {

namespace detail {

constexpr std::string_view universal_tag_name(std::uint32_t n) noexcept {
    switch (n) {
    case 1:
        return "BOOLEAN";
    case 2:
        return "INTEGER";
    case 3:
        return "BIT STRING";
    case 4:
        return "OCTET STRING";
    case 5:
        return "NULL";
    case 6:
        return "OBJECT IDENTIFIER";
    case 7:
        return "ObjectDescriptor";
    case 8:
        return "EXTERNAL";
    case 9:
        return "REAL";
    case 10:
        return "ENUMERATED";
    case 11:
        return "EMBEDDED PDV";
    case 12:
        return "UTF8String";
    case 13:
        return "RELATIVE-OID";
    case 14:
        return "TIME";
    case 16:
        return "SEQUENCE";
    case 17:
        return "SET";
    case 18:
        return "NumericString";
    case 19:
        return "PrintableString";
    case 20:
        return "TeletexString";
    case 21:
        return "VideotexString";
    case 22:
        return "IA5String";
    case 23:
        return "UTCTime";
    case 24:
        return "GeneralizedTime";
    case 25:
        return "GraphicString";
    case 26:
        return "VisibleString";
    case 27:
        return "GeneralString";
    case 28:
        return "UniversalString";
    case 29:
        return "CHARACTER STRING";
    case 30:
        return "BMPString";
    case 31:
        return "DATE";
    case 32:
        return "TIME-OF-DAY";
    case 33:
        return "DATE-TIME";
    case 34:
        return "DURATION";
    case 35:
        return "OID-IRI";
    case 36:
        return "RELATIVE-OID-IRI";
    default:
        return {};
    }
}

inline std::string tag_to_string(tag t) {
    if (t.cls == tag_class::universal) {
        auto name = universal_tag_name(t.number);
        if (!name.empty())
            return std::string(name);
        return std::format("[UNIVERSAL {}]", t.number);
    }
    switch (t.cls) {
    case tag_class::application:
        return std::format("[APPLICATION {}]", t.number);
    case tag_class::context_specific:
        return std::format("[{}]", t.number);
    case tag_class::private_:
        return std::format("[PRIVATE {}]", t.number);
    default:
        return std::format("[UNIVERSAL {}]", t.number);
    }
}

inline void dump_value(const value & v, std::string & out, int indent) {
    out.append(static_cast<std::size_t>(indent) * 2, ' ');
    out += tag_to_string(v.tag);
    if (v.constructed) {
        out += std::format(" ({} elem)\n", v.children.size());
        for (const auto & c : v.children)
            dump_value(c, out, indent + 1);
    } else {
        auto s = v.content.span();
        out += std::format(" ({} bytes)", s.size());
        constexpr std::size_t preview = 16;
        if (!s.empty()) {
            out += " ";
            for (std::size_t i = 0; i < s.size() && i < preview; ++i)
                out += std::format("{:02X}", std::to_integer<unsigned>(s[i]));
            if (s.size() > preview)
                out += "...";
        }
        out += '\n';
    }
}

} // namespace detail

// Human-readable tree dump of a parsed value.
inline std::string dump(const value & v) {
    std::string out;
    detail::dump_value(v, out, 0);
    return out;
}

} // namespace asn1

template<>
struct std::formatter<asn1::tag> : std::formatter<std::string> {
    auto format(const asn1::tag & t, std::format_context & ctx) const {
        return std::formatter<std::string>::format(asn1::detail::tag_to_string(t), ctx);
    }
};

template<>
struct std::formatter<asn1::errc> : std::formatter<std::string_view> {
    auto format(asn1::errc c, std::format_context & ctx) const {
        return std::formatter<std::string_view>::format(asn1::message(c), ctx);
    }
};

template<>
struct std::formatter<asn1::error> : std::formatter<std::string> {
    auto format(const asn1::error & e, std::format_context & ctx) const {
        std::string s;
        if (e.code == asn1::errc::tag_mismatch) {
            s = std::format("{} at offset {:#x}: expected {}, got {}", asn1::message(e.code), e.offset, e.expected,
                            e.actual);
        } else {
            s = std::format("{} at offset {:#x}", asn1::message(e.code), e.offset);
        }
        return std::formatter<std::string>::format(s, ctx);
    }
};

template<>
struct std::formatter<asn1::oid> : std::formatter<std::string> {
    auto format(const asn1::oid & o, std::format_context & ctx) const {
        return std::formatter<std::string>::format(o.to_string(), ctx);
    }
};
