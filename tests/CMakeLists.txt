include(FetchContent)
# doctest v2.4.11 declares a pre-3.5 CMake minimum, which CMake 4 rejects.
set(CMAKE_POLICY_VERSION_MINIMUM 3.5)
FetchContent_Declare(
  doctest
  GIT_REPOSITORY https://github.com/doctest/doctest.git
  GIT_TAG v2.4.11
  GIT_SHALLOW TRUE)
FetchContent_MakeAvailable(doctest)

add_executable(asn1_tests
  main.cpp
  test_reader.cpp
  test_primitives.cpp
  test_strings_time.cpp
  test_structures.cpp
  test_review_regressions.cpp)
target_link_libraries(asn1_tests PRIVATE asn1::asn1 doctest::doctest)
if(MSVC)
  target_compile_options(asn1_tests PRIVATE /W4)
else()
  target_compile_options(asn1_tests PRIVATE -Wall -Wextra -Wpedantic)
endif()

add_test(NAME asn1_tests COMMAND asn1_tests)
