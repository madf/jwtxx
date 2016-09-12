enable_language(CXX)

find_package(Boost 1.55.0 REQUIRED)
find_package(OpenSSL 0.9.8 REQUIRED)

include_directories(${jwtxx_SOURCE_DIR}/include)
include_directories(${Boost_INCLUDE_DIRS})

add_executable(nonetest nonetest.cpp)
target_link_libraries(nonetest jwtxx ${OPENSSL_LIBRARIES})

add_test(none nonetest)
