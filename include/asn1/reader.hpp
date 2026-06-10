// asn1/reader.hpp — L0: bounds-checked X.690 TLV parsing over a byte span.
//
// Zero-allocation: every parsed element is a pair of spans into the input.
// Indefinite-length encodings (§8.1.3.6) are resolved here by scanning to
// the matching end-of-contents octets, depth-limited.
#pragma once

#include <cstddef>
#include <cstdint>
#include <span>

#include "core.hpp"
#include "rules.hpp"

namespace asn1 {

// One parsed TLV. `content` is the contents octets (for indefinite form:
// without the EOC); `full` is identifier..end (for indefinite: incl. EOC).
struct element {
    asn1::tag tag{};
    bool constructed = false;
    bool indefinite = false;
    bytes_view content{};
    bytes_view full{};
    std::size_t offset = 0; // absolute offset of the first identifier octet
};

template<encoding_rules R>
class reader {
public:
    constexpr reader(bytes_view data, std::uint32_t max_depth, std::size_t base_offset = 0) noexcept
        : data_(data),
          max_depth_(max_depth),
          base_(base_offset) {}

    [[nodiscard]] constexpr bool empty() const noexcept {
        return pos_ >= data_.size();
    }
    [[nodiscard]] constexpr std::size_t offset() const noexcept {
        return base_ + pos_;
    }
    [[nodiscard]] constexpr bytes_view remaining() const noexcept {
        return data_.subspan(pos_);
    }

    // Parse the next complete TLV without consuming it.
    [[nodiscard]] constexpr result<element> peek() const {
        auto p = parse(pos_, 0);
        if (!p)
            return std::unexpected(p.error());
        if (p->is_eoc)
            return detail::fail(errc::unbalanced_eoc, base_ + pos_);
        return p->el;
    }

    // Parse and consume the next complete TLV.
    constexpr result<element> next() {
        auto p = parse(pos_, 0);
        if (!p)
            return std::unexpected(p.error());
        if (p->is_eoc)
            return detail::fail(errc::unbalanced_eoc, base_ + pos_);
        pos_ = p->end;
        return p->el;
    }

private:
    struct parsed {
        element el{};
        std::size_t end = 0; // position just past this TLV (incl. EOC)
        bool is_eoc = false;
    };

    [[nodiscard]] constexpr result<parsed> parse(std::size_t pos, std::uint32_t depth) const {
        const std::size_t start = pos;
        if (pos >= data_.size())
            return detail::fail(errc::truncated, base_ + pos);

        const auto b0 = std::to_integer<std::uint8_t>(data_[pos]);

        // §8.1.5: end-of-contents is 00 00. A lone 0x00 with nonzero length is
        // malformed (universal tag 0 is reserved for EOC).
        if (b0 == 0x00) {
            if (pos + 1 >= data_.size())
                return detail::fail(errc::truncated, base_ + pos + 1);
            if (std::to_integer<std::uint8_t>(data_[pos + 1]) != 0x00)
                return detail::fail(errc::invalid_tag, base_ + pos);
            parsed p;
            p.is_eoc = true;
            p.end = pos + 2;
            p.el.offset = base_ + pos;
            return p;
        }

        // --- identifier octets (§8.1.2) ---
        element el;
        el.offset = base_ + pos;
        el.tag.cls = static_cast<tag_class>(b0 >> 6);
        el.constructed = (b0 & 0x20) != 0;
        std::uint32_t number = b0 & 0x1F;
        ++pos;

        if (number == 0x1F) { // high tag number form (§8.1.2.4)
            number = 0;
            bool first = true;
            while (true) {
                if (pos >= data_.size())
                    return detail::fail(errc::truncated, base_ + pos);
                const auto c = std::to_integer<std::uint8_t>(data_[pos]);
                ++pos;
                // §8.1.2.4.2 c: bits 7-1 of the first subsequent octet shall not
                // all be zero (no 0x80 padding — minimal even in BER).
                if (first && (c & 0x7F) == 0)
                    return detail::fail(errc::invalid_tag, base_ + pos - 1);
                first = false;
                if (number > (0xFFFFFFFFu >> 7))
                    return detail::fail(errc::invalid_tag, base_ + pos - 1);
                number = (number << 7) | (c & 0x7F);
                if ((c & 0x80) == 0)
                    break;
            }
            // §8.1.2.2: tag numbers 0-30 shall use the low form.
            if (number < 31)
                return detail::fail(errc::invalid_tag, base_ + start);
        }
        el.tag.number = number;

        // --- length octets (§8.1.3) ---
        if (pos >= data_.size())
            return detail::fail(errc::truncated, base_ + pos);
        const std::size_t len_off = pos;
        const auto l0 = std::to_integer<std::uint8_t>(data_[pos]);
        ++pos;

        std::uint64_t length = 0;
        if (l0 < 0x80) { // definite short form (§8.1.3.4)
            length = l0;
        } else if (l0 == 0x80) { // indefinite form (§8.1.3.6)
            // §8.1.3.2 a: primitive => definite form only.
            if (!el.constructed)
                return detail::fail(errc::indefinite_not_allowed, base_ + len_off);
            if (!R::allow_indefinite_length)
                return detail::fail(errc::indefinite_not_allowed, base_ + len_off);
            el.indefinite = true;
        } else if (l0 == 0xFF) { // §8.1.3.5 c: reserved
            return detail::fail(errc::invalid_length, base_ + len_off);
        } else { // definite long form (§8.1.3.5)
            // Not const: the BER branch below strips leading zero octets.
            // NOLINTNEXTLINE(misc-const-correctness) -- mutated in a discarded constexpr branch
            std::size_t n = l0 & 0x7F;
            if (n > data_.size() - pos)
                return detail::fail(errc::truncated, base_ + data_.size());
            if constexpr (R::require_minimal_length) {
                if (std::to_integer<std::uint8_t>(data_[pos]) == 0)
                    return detail::fail(errc::non_minimal_length, base_ + len_off);
            } else {
                // §8.1.3.5 allows up to 126 length octets and BER imposes no
                // minimality; only the significant octets are bounded below.
                while (n > 0 && std::to_integer<std::uint8_t>(data_[pos]) == 0) {
                    ++pos;
                    --n;
                }
            }
            if (n > sizeof(std::uint64_t))
                return detail::fail(errc::invalid_length, base_ + len_off);
            for (std::size_t i = 0; i < n; ++i)
                length = (length << 8) | std::to_integer<std::uint8_t>(data_[pos + i]);
            pos += n;
            if constexpr (R::require_minimal_length) {
                if (length < 0x80)
                    return detail::fail(errc::non_minimal_length, base_ + len_off);
            }
        }

        // --- contents octets ---
        if (!el.indefinite) {
            if (length > data_.size() - pos)
                return detail::fail(errc::length_overflow, base_ + len_off);
            el.content = data_.subspan(pos, static_cast<std::size_t>(length));
            pos += static_cast<std::size_t>(length);
        } else {
            // Scan nested TLVs until the matching EOC. Children are themselves
            // fully parsed (recursively), so the depth limit bounds the scan.
            if (depth >= max_depth_)
                return detail::fail(errc::depth_exceeded, base_ + start);
            const std::size_t content_start = pos;
            while (true) {
                auto child = parse(pos, depth + 1);
                if (!child)
                    return std::unexpected(child.error());
                if (child->is_eoc) {
                    el.content = data_.subspan(content_start, pos - content_start);
                    pos = child->end;
                    break;
                }
                pos = child->end;
            }
        }

        el.full = data_.subspan(start, pos - start);
        return parsed{el, pos, false};
    }

    bytes_view data_;
    std::size_t pos_ = 0;
    std::uint32_t max_depth_;
    std::size_t base_;
};

} // namespace asn1
