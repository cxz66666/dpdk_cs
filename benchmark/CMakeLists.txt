cmake_minimum_required(VERSION 3.10)

project(DPDK_SAMPLE)


set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_SOURCE_DIR}/bin)
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_SOURCE_DIR}/build)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_SOURCE_DIR}/lib)


set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -O3 -DALLOW_EXPERIMENTAL_API -std=c++20 -Wall -Wextra -Werror -pedantic")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wno-unused-function -Wno-missing-braces")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wno-nested-anon-types -Wno-keyword-macro -Wno-deprecated-declarations")

add_definitions(-DALLOW_EXPERIMENTAL_API)


find_package(PkgConfig REQUIRED)
pkg_check_modules(LIBDPDK IMPORTED_TARGET libdpdk)

if (LIBDPDK_FOUND)
    message(STATUS "LIBDPDK found")
else ()
    message(FATAL_ERROR "LIBDPDK not found")
    return()
endif ()


#sub-project: HdrHistogram
include_directories(${CMAKE_SOURCE_DIR}/HdrHistogram/include)

include_directories("${LIBDPDK_INCLUDE_DIRS}")

include_directories("${CMAKE_SOURCE_DIR}/client/config")


add_subdirectory(${CMAKE_SOURCE_DIR}/HdrHistogram)

set(LIBRARIES ${LIBRARIES} PkgConfig::LIBDPDK hdr_histogram_static)


set(UTILSOURCES )

add_subdirectory(${CMAKE_SOURCE_DIR}/client/bandwidth)
add_subdirectory(${CMAKE_SOURCE_DIR}/client/delay)
add_subdirectory(${CMAKE_SOURCE_DIR}/client/delay_mt)
add_subdirectory(${CMAKE_SOURCE_DIR}/server/l2fwd)