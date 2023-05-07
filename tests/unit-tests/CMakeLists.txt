cmake_minimum_required(VERSION 3.14)
project(cpp_lite_sockets__unit_tests)

# GoogleTest requires at least C++14
set(CMAKE_CXX_STANDARD 14)

include(FetchContent)
FetchContent_Declare(
  googletest
  URL https://github.com/google/googletest/archive/03597a01ee50ed33e9dfd640b249b4be3799d395.zip
)
# For Windows: Prevent overriding the parent project's compiler/linker settings
set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)
FetchContent_MakeAvailable(googletest)

enable_testing()

FILE(GLOB unit_test_sources ./*.cpp)

include_directories(AFTER ../../include)

add_executable(
  unit_tests
  ${unit_test_sources}
)

target_link_libraries(
  unit_tests
  GTest::gtest_main
)

include(GoogleTest)
gtest_discover_tests(unit_tests)