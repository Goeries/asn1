// asn1/codec.hpp — the user-facing facade: asn1::codec<Rules>.
//
//   auto v = asn1::ber_codec::decode<MyStruct>(bytes);   // result<MyStruct>
//   auto b = asn1::ber_codec::encode(v);                 // result<vector<byte>>
#pragma once

#include <utility>
#include <vector>

#include "core.hpp"
#include "decoder.hpp"
#include "encoder.hpp"
#include "rules.hpp"
#include "traits.hpp"

namespace asn1 {

template<encoding_rules R>
struct codec {
    using rules = R;

    // Decode one value; the input must contain exactly one element.
    template<class T>
    static result<T> decode(bytes_view in, decode_options opt = {}) {
        decoder<R> d(in, opt);
        auto r = d.template read<T>();
        if (!r)
            return r;
        if (auto e = d.expect_end(); !e)
            return std::unexpected(e.error());
        return r;
    }

    // Decode one value and return the unconsumed rest of the input.
    template<class T>
    static result<std::pair<T, bytes_view>> decode_partial(bytes_view in, decode_options opt = {}) {
        decoder<R> d(in, opt);
        auto r = d.template read<T>();
        if (!r)
            return std::unexpected(r.error());
        return std::pair<T, bytes_view>(std::move(*r), d.remaining());
    }

    template<class T>
    static result<std::vector<std::byte>> encode(const T & v) {
        encoder<R> e;
        auto r = e.write(v);
        if (!r)
            return std::unexpected(r.error());
        return std::move(e).finish();
    }
};

using ber_codec = codec<ber>;
using der_codec = codec<der>;

} // namespace asn1
