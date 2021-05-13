
include(FetchContent)

FetchContent_Declare(
    googletest
    GIT_REPOSITORY https://github.com/google/googletest.git
    GIT_TAG        release-1.8.0
)

FetchContent_MakeAvailable(googletest)

include_directories(${ROOT_DIR}/Inc ${GTEST_INCLUDE_DIRS})

add_executable(test_ip_filter.out test_ip_filter.cpp)
target_link_libraries(test_ip_filter.out gtest_main ip_filter)

include(GoogleTest)

gtest_discover_tests(test_ip_filter.out)