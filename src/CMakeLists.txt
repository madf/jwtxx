include_directories(${jwtxx_SOURCE_DIR}/include)

include_directories(${OPENSSL_INCLUDE_DIR})
include_directories(${JANSSON_INCLUDE_DIR})

add_library(jwtxx STATIC jwt.cpp utils.cpp json.cpp)
