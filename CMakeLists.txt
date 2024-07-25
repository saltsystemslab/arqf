cmake_minimum_required(VERSION 3.16.3)
project(Memento
        VERSION 1.0
        HOMEPAGE_URL https://github.com/marcocosta97/grafite)

option(BUILD_TESTS "Build the tests" ON)
option(BUILD_EXAMPLES "Build the examples" ON)
option(BUILD_BENCHMARKS "Build the benchmark targets" ON)
option(USE_BOOST "Use the Boost library" ON)
option(USE_MULTI_THREADED "Use multi-threaded version of the library" OFF)
option(PRINT_DEBUG_LOG "Print debug log messages" OFF)

if(CMAKE_BUILD_TYPE STREQUAL "Debug" AND PRINT_DEBUG_LOG)
  target_compile_options(mementolib PUBLIC -DDEBUG)
endif()

if (BUILD_BENCHMARKS)
    message(STATUS "Building benchmarks")
    add_subdirectory(bench)
endif ()
