cmake_minimum_required(VERSION 2.6)

set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${CMAKE_SOURCE_DIR}/cmake/modules")

project(jwtxx)

enable_language(CXX)

set(VERSION_MAJOR 1)
set(VERSION_MINOR 0)
set(VERSION_PATCH 0)

set(CMAKE_CXX_FLAGS "-W -Wall -Wextra -pedantic -std=c++0x -Wno-unused-local-typedefs")

set(JANSSON_FIND_REQUIRED 1)
find_package(Jansson)

find_package(Boost 1.55.0 REQUIRED)
find_package(OpenSSL 0.9.8 REQUIRED)

include_directories(${jwtxx_SOURCE_DIR}/include)
include_directories(${Boost_INCLUDE_DIRS})

enable_testing()

add_subdirectory(src)
add_subdirectory(tests)
