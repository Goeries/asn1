cmake_minimum_required(VERSION 3.28)
project(asn1 VERSION 0.1.0 LANGUAGES CXX)

add_library(asn1 INTERFACE)
add_library(asn1::asn1 ALIAS asn1)
target_compile_features(asn1 INTERFACE cxx_std_23)
target_include_directories(asn1 INTERFACE
  $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
  $<INSTALL_INTERFACE:include>)

if(PROJECT_IS_TOP_LEVEL)
  # No C++ modules here; skip scanning so clang builds don't need clang-scan-deps.
  set(CMAKE_CXX_SCAN_FOR_MODULES OFF)

  option(ASN1_BUILD_TESTS "Build the asn1 test suite" ON)
  option(ASN1_BUILD_FUZZERS "Build libFuzzer targets (requires clang)" OFF)

  if(ASN1_BUILD_TESTS)
    enable_testing()
    add_subdirectory(tests)
  endif()
  if(ASN1_BUILD_FUZZERS)
    add_subdirectory(fuzz)
  endif()
endif()
