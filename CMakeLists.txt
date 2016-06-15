cmake_minimum_required(VERSION 2.8.7)
project(syscallfilter)
include(CTest)

set(SOURCES
    main.cpp
    syscallfilter.cpp
)

set(CMAKE_CXX_FLAGS "-std=c++11 -Wall")
add_executable(syscallfilter ${SOURCES})

add_test(NAME test COMMAND bash ${CMAKE_CURRENT_SOURCE_DIR}/test.sh)

add_custom_target(format-all
  COMMAND find . \( -name "*.h" -o -name "*.cpp" -o -name "*.ipp" \) -exec clang-format -i {} +
  WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
  COMMENT "Formatting C++ code with clang-format" VERBATIM
)
