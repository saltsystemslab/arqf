cmake_minimum_required(VERSION 3.16.3)
project(arqf
  VERSION 1.0)

# TODO(chesetti): Add debug/profile/ARCH options.
# TODO(chesetti): Figure out if link dependencies should be PUBLIC or PRIVATE.


set(SPLINTERDB_PATH ./external/splinterdb/build/release/lib)
get_filename_component(SPLINTERDB_FULL_PATH ${SPLINTERDB_PATH} ABSOLUTE)

message(STATUS "SPLINTERDB LIB: ${SPLINTERDB_FULL_PATH}")

add_library(arqflib STATIC
  ./src/gqf.c
  ./src/gqf_file.c
  ./src/ll_table.c
  ./src/partitioned_counter.c
  ./src/rand_util.c
  ./src/splinter_util.c
  ./src/hashutil.c
  ./src/arqf.c
  ./src/arqf_inmem.cc
  ./src/arqf_wt.cc
)
# TODO(chesetti): Add wiredtiger as a submodule and update instructions.
target_include_directories(arqflib PUBLIC . ./include ./external/splinterdb/include /home/chesetti/local/include)
# The order seems to matter here, aio and xxhash need to compe after SplinterDB.
target_link_libraries(arqflib PUBLIC pthread ssl crypto m ${SPLINTERDB_FULL_PATH}/libsplinterdb.a aio xxhash)
if(CMAKE_BUILD_TYPE STREQUAL "Debug" )
  target_compile_options(arqflib PUBLIC -Og -m64 -DDEBUG -DSPLINTERDB_PLATFORM_DIR=platform_linux -DSKIP_BOOL_DEF -D_GNU_SOURCE)
else()
  target_compile_options(arqflib PUBLIC -Ofast -m64 -march=native -DNDEBUG -DSPLINTERDB_PLATFORM_DIR=platform_linux -DSKIP_BOOL_DEF -D_GNU_SOURCE)
endif()

# I don't think the -rpath option is working...
#target_link_options(arqflib PUBLIC  "-Wl,-rpath=${SPLINTERDB_FULL_PATH}")

add_executable(test_micro ./test/test_micro.c ./src/test_driver.c)
target_include_directories(test_micro  PUBLIC . ./include ./external/splinterdb/include)
target_compile_options(test_micro PUBLIC -O3 -m64 -DNDEBUG)
target_link_libraries(test_micro  PUBLIC arqflib pthread ssl m ${SPLINTERDB_FULL_PATH}/libsplinterdb.a aio xxhash)

add_executable(test_encoding ./test/test_encoding.c)
target_include_directories(test_encoding  PUBLIC . ./include ./external/splinterdb/include)
target_link_libraries(test_encoding  PUBLIC arqflib ${SPLINTERDB_FULL_PATH}/libsplinterdb.a)
target_compile_options(test_encoding PUBLIC -Og -m64 -DDEBUG -DSPLINTERDB_PLATFORM_DIR=platform_linux -DSKIP_BOOL_DEF -D_GNU_SOURCE)
