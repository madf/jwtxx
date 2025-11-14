cmake_minimum_required(VERSION 3.5...4.1)

add_executable(hs256_example hs256_example.cpp)
target_link_libraries(hs256_example jwtxx)

add_executable(rs256_example rs256_example.cpp)
target_link_libraries(rs256_example jwtxx)

add_executable(key_reuse_example key_reuse_example.cpp)
target_link_libraries(key_reuse_example jwtxx)

add_executable(claims_types_example claims_types_example.cpp)
target_link_libraries(claims_types_example jwtxx)

add_executable(validation_example validation_example.cpp)
target_link_libraries(validation_example jwtxx)

set_target_properties(
    hs256_example
    rs256_example
    key_reuse_example
    claims_types_example
    validation_example
    PROPERTIES
        CXX_STANDARD 17
        CXX_STANDARD_REQUIRED ON
        CXX_EXTENSIONS OFF
)
