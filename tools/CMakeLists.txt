project(jwttool VERSION 1.0.0)

enable_language(CXX)

find_package(Boost 1.46.0 REQUIRED)

include_directories(${PROJECT_BINARY_DIR}) # toolversion.h
include_directories(${jwtxx_BINARY_DIR}/include) # jwtxx/version.h
include_directories(${Boost_INCLUDE_DIRS})

add_custom_target(generate_tool_version COMMAND ${CMAKE_COMMAND} -D SOURCE_FILE=${PROJECT_SOURCE_DIR}/toolversion.h.in -D DEST_FILE=${PROJECT_BINARY_DIR}/toolversion.h -D PROJECT_VERSION=${PROJECT_VERSION} -P ${jwtxx_SOURCE_DIR}/cmake/version.cmake)

add_executable(${PROJECT_NAME} jwttool.cpp)
add_dependencies(${PROJECT_NAME} generate_tool_version)
target_link_libraries(${PROJECT_NAME} jwtxx ${OPENSSL_LIBRARIES} ${JANSSON_LIBRARIES})

install(TARGETS ${PROJECT_NAME} RUNTIME DESTINATION bin)
