include_directories(${jwtxx_SOURCE_DIR}/include)

find_package(OpenSSL)

include_directories(${OPENSSL_INCLUDE_DIR})

add_library(jwtxx STATIC jwt.cpp utils.cpp)
