// asn1/value.hpp — L2: a generic DOM over arbitrary BER, for tooling and
// schema-less inspection (dumpasn1-style).
//
// The tree holds views into the input buffer; keep the buffer alive, or
// call to_owned() to detach.
#pragma once

#include <string>
#include <vector>

#include "core.hpp"
#include "decoder.hpp"
#include "encoder.hpp"
#include "reader.hpp"
#include "rules.hpp"
#include "types.hpp"

namespace asn1 {

struct value {
    asn1::tag tag{};
    bool constructed = false;
    bytes content{};             // primitive contents, or raw constructed span
    std::vector<value> children; // parsed contents when constructed

    // Parse a complete element (and, recursively, its children).
    template<encoding_rules R = ber>
    static result<value> parse(bytes_view in, decode_options opt = {}) {
        reader<R> rd(in, opt.max_depth);
        auto el = rd.next();
        if (!el)
            return std::unexpected(el.error());
        auto v = from_element<R>(*el, opt, 0);
        if (!v)
            return v;
        if (!rd.empty())
            return detail::fail(errc::trailing_data, rd.offset());
        return v;
    }

    value & to_owned() {
        content.to_owned();
        for (auto & c : children)
            c.to_owned();
        return *this;
    }

    // Re-encode (always definite-length).
    [[nodiscard]] std::vector<std::byte> to_bytes() const {
        std::vector<std::byte> out;
        encode_to(out);
        return out;
    }

    // Typed accessors for universal primitives.
    template<encoding_rules R = ber>
    [[nodiscard]] result<std::int64_t> as_integer() const {
        return reparse<R, std::int64_t>();
    }
    template<encoding_rules R = ber>
    [[nodiscard]] result<bool> as_bool() const {
        return reparse<R, bool>();
    }
    template<encoding_rules R = ber>
    [[nodiscard]] [[nodiscard]] result<oid> as_oid() const {
        return reparse<R, oid>();
    }
    template<encoding_rules R = ber>
    [[nodiscard]] result<std::string> as_text() const {
        auto buf = to_bytes();
        decoder<R> d(buf, {});
        return d.read_character_string(tag);
    }

    friend bool operator==(const value & a, const value & b) noexcept {
        return a.tag == b.tag && a.constructed == b.constructed &&
               (a.constructed ? a.children == b.children : a.content == b.content);
    }

private:
    template<encoding_rules R>
    static result<value> from_element(const element & el, const decode_options & opt, std::uint32_t depth) {
        value v;
        v.tag = el.tag;
        v.constructed = el.constructed;
        v.content = bytes::view(el.content);
        if (el.constructed) {
            if (depth + 1 > opt.max_depth)
                return detail::fail(errc::depth_exceeded, el.offset);
            // Children's base is the absolute offset of the contents octets,
            // so nested errors report absolute input positions.
            const auto content_base = el.offset + static_cast<std::size_t>(el.content.data() - el.full.data());
            reader<R> rd(el.content, opt.max_depth, content_base);
            while (!rd.empty()) {
                auto child = rd.next();
                if (!child)
                    return std::unexpected(child.error());
                auto cv = from_element<R>(*child, opt, depth + 1);
                if (!cv)
                    return cv;
                v.children.push_back(std::move(*cv));
            }
        }
        return v;
    }

    void encode_to(std::vector<std::byte> & out) const {
        detail::put_identifier(out, tag, constructed);
        if (!constructed) {
            auto s = content.span();
            detail::put_length(out, s.size());
            out.insert(out.end(), s.begin(), s.end());
        } else {
            std::vector<std::byte> inner;
            for (const auto & c : children)
                c.encode_to(inner);
            detail::put_length(out, inner.size());
            out.insert(out.end(), inner.begin(), inner.end());
        }
    }

    template<encoding_rules R, class T>
    [[nodiscard]] result<T> reparse() const {
        auto buf = to_bytes();
        decoder<R> d(buf, {});
        return d.template read<T>();
    }
};

} // namespace asn1
