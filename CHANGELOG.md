# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0] - 2026-06-10

Initial release.

### Added

- Header-only C++23 ASN.1 codec with X.690 encoding rules as policy types
  (`asn1::ber`, `asn1::der`).
- Zero-allocation TLV reader: high-tag-number form, short/long/indefinite
  lengths, EOC matching, depth limits.
- Typed codec for all common universal types: BOOLEAN, INTEGER, ENUMERATED,
  NULL, REAL (binary and decimal forms), OCTET STRING, BIT STRING, OID,
  RELATIVE-OID, restricted character strings, UTCTime/GeneralizedTime.
- SEQUENCE (OF), SET OF with DER ordering, CHOICE, OPTIONAL, ANY, and
  IMPLICIT/EXPLICIT tagging wrappers.
- Automatic struct mapping: plain aggregates encode/decode positionally with
  no macros or codegen, with compile-time schema checks (distinct CHOICE
  tags, OPTIONAL ambiguity).
- Schema-less DOM (`asn1::value`) with `asn1::dump()` pretty-printing.
- `std::expected`-based errors carrying error code and byte offset.
- Hardening against the classic BER decoder pitfalls: length overflow,
  recursion depth, OID arc overflow.
- doctest suite covering the X.690 normative examples, known-answer vectors,
  error paths and round-trip property tests; libFuzzer harness in `fuzz/`.
- CI: GCC, Clang, MSVC and MinGW builds plus clang-format and clang-tidy
  checks.
- clang-format and clang-tidy configurations; the codebase is tidy-clean.

[Unreleased]: https://github.com/goeries/asn1/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/goeries/asn1/releases/tag/v0.1.0
