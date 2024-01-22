cmake_minimum_required(VERSION 3.10)

project(DPDK_SAMPLE)


if (CMAKE_SYSTEM_PROCESSOR MATCHES "aarch64")
    message(STATUS "Compile on DPU")
    message(STATUS "Output Dir is /bin_dpu")
    set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_SOURCE_DIR}/bin_dpu)
    set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_SOURCE_DIR}/build_dpu)
    set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_SOURCE_DIR}/lib_dpu)

elseif(CMAKE_SYSTEM_PROCESSOR MATCHES "x86_64")
    message(STATUS "Compile on HOST")
    message(STATUS "Output Dir is /bin_host")
    set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_SOURCE_DIR}/bin_host)
    set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_SOURCE_DIR}/build_host)
    set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_SOURCE_DIR}/lib_host)
else()
    # 在其他架构下的逻辑代码
    message("Unknown architecture detected")
    return()
endif ()


set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -O3 -DALLOW_EXPERIMENTAL_API -Wall -Wextra -Werror -pedantic")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wno-unused-function -Wno-missing-braces")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wno-nested-anon-types -Wno-keyword-macro -Wno-deprecated-declarations")

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -O3 -DALLOW_EXPERIMENTAL_API -std=c++20 -Wall -Wextra -Werror -pedantic")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wno-unused-function -Wno-missing-braces")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wno-nested-anon-types -Wno-keyword-macro -Wno-deprecated-declarations")
# if we don't add this, we will get *** stack smashing detected ***: terminated error
add_compile_options(-fno-stack-protector)



find_package(PkgConfig REQUIRED)
pkg_check_modules(LIBDPDK IMPORTED_TARGET libdpdk)

if (LIBDPDK_FOUND)
    message(STATUS "LIBDPDK found")
else ()
    message(FATAL_ERROR "LIBDPDK not found")
    return()
endif ()


#sub-project: HdrHistogram
include_directories(${CMAKE_SOURCE_DIR}/third_party/HdrHistogram/include)

include_directories("${LIBDPDK_INCLUDE_DIRS}")

include_directories("${CMAKE_SOURCE_DIR}/client/config")
include_directories("${CMAKE_SOURCE_DIR}/common")


add_subdirectory(${CMAKE_SOURCE_DIR}/third_party/HdrHistogram)

set(LIBRARIES ${LIBRARIES} PkgConfig::LIBDPDK hdr_histogram)


set(UTILSOURCES )

add_subdirectory(${CMAKE_SOURCE_DIR}/client/bandwidth)
add_subdirectory(${CMAKE_SOURCE_DIR}/client/delay)
add_subdirectory(${CMAKE_SOURCE_DIR}/client/delay_mt)
add_subdirectory(${CMAKE_SOURCE_DIR}/client/daemon)
add_subdirectory(${CMAKE_SOURCE_DIR}/client/workingset)
add_subdirectory(${CMAKE_SOURCE_DIR}/client/bg_bw_c2s)
add_subdirectory(${CMAKE_SOURCE_DIR}/client/bg_bw_s2c)
add_subdirectory(${CMAKE_SOURCE_DIR}/client/bg_bw_c2s2c)
add_subdirectory(${CMAKE_SOURCE_DIR}/server/l2fwd)
add_subdirectory(${CMAKE_SOURCE_DIR}/server/l2fwd_client)
add_subdirectory(${CMAKE_SOURCE_DIR}/server/l2fwd_workingset)
add_subdirectory(${CMAKE_SOURCE_DIR}/server/l2fwd_random_access)