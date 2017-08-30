cmake_minimum_required(VERSION 3.0)

set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${CMAKE_SOURCE_DIR}/cmake/modules")

project(jwtxx VERSION 1.1.6)

enable_language(CXX)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -W -Wall -Wextra -std=c++0x")

set(JANSSON_FIND_REQUIRED 1)
find_package(Jansson)

find_package(OpenSSL 0.9.8 REQUIRED)

find_package(Boost 1.46.0)

try_compile(HAS_OVERRIDE_FEATURE ${CMAKE_CURRENT_BINARY_DIR} "${PROJECT_SOURCE_DIR}/checks/checkoverride.cpp")
if(NOT HAS_OVERRIDE_FEATURE)
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Doverride=")
endif(NOT HAS_OVERRIDE_FEATURE)

include_directories(${jwtxx_SOURCE_DIR}/include)

add_subdirectory(src)
add_subdirectory(tools EXCLUDE_FROM_ALL)

if(Boost_FOUND)
    enable_testing()
    add_subdirectory(tests EXCLUDE_FROM_ALL)
endif(Boost_FOUND)

add_custom_target(cppcheck COMMAND cppcheck --enable=all --std=c++11 -I ${jwtxx_SOURCE_DIR}/include ${jwtxx_SOURCE_DIR}/src ${jwtxx_SOURCE_DIR}/tools)
