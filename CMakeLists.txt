cmake_minimum_required(VERSION 2.6)

project(jwtxx)

enable_language(CXX)

set(VERSION_MAJOR 1)
set(VERSION_MINOR 0)
set(VERSION_PATCH 0)

set(CMAKE_CXX_FLAGS "-W -Wall -Wextra -pedantic -std=c++0x")

add_subdirectory(src)
