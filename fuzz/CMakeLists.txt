if(NOT CMAKE_CXX_COMPILER_ID MATCHES "Clang")
  message(WARNING "ASN1_BUILD_FUZZERS requires clang; skipping fuzz targets")
  return()
endif()

add_executable(asn1_fuzz_parse fuzz_parse.cpp)
target_link_libraries(asn1_fuzz_parse PRIVATE asn1::asn1)
target_compile_options(asn1_fuzz_parse PRIVATE -fsanitize=fuzzer,address -g)
target_link_options(asn1_fuzz_parse PRIVATE -fsanitize=fuzzer,address)
