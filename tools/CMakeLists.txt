enable_language(CXX)

find_package(Boost 1.46.0 REQUIRED)

include_directories(${Boost_INCLUDE_DIRS})

add_executable(jwttool jwttool.cpp)
target_link_libraries(jwttool jwtxx ${OPENSSL_LIBRARIES} ${JANSSON_LIBRARIES})
