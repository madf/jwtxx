cmake_minimum_required(VERSION 2.6)

set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${CMAKE_SOURCE_DIR}/cmake/modules")

project(jwtxx)

enable_language(CXX)

set(VERSION_MAJOR 1)
set(VERSION_MINOR 0)
set(VERSION_PATCH 0)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -W -Wall -Wextra -std=c++0x")

set(JANSSON_FIND_REQUIRED 1)
find_package(Jansson)

find_package(OpenSSL 0.9.8 REQUIRED)

try_compile(HAS_OVERRIDE_FEATURE ${CMAKE_CURRENT_BINARY_DIR} "${CMAKE_SOURCE_DIR}/checks/checkoverride.cpp")
if(NOT HAS_OVERRIDE_FEATURE)
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Doverride=")
endif(NOT HAS_OVERRIDE_FEATURE)

include_directories(${jwtxx_SOURCE_DIR}/include)

enable_testing()

add_subdirectory(src)
add_subdirectory(tools)
add_subdirectory(tests)

add_custom_target(cppcheck COMMAND /usr/bin/cppcheck --enable=all --std=c++11 -I ${jwtxx_SOURCE_DIR}/include ${jwtxx_SOURCE_DIR}/src)
