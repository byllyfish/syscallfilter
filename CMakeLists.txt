cmake_minimum_required(VERSION 2.8.8)
project(syscallfilter)


set(SOURCES
    main.cpp
    syscallfilter.cpp
)

set(CMAKE_CXX_FLAGS -std=c++11)
add_executable(syscallfilter ${SOURCES})
