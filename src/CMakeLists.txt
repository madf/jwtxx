include_directories(${PROJECT_SOURCE_DIR}/include)
include_directories(${PROJECT_BINARY_DIR}/include) # jwtxx/version.h

include_directories(${OPENSSL_INCLUDE_DIR})
include_directories(${JANSSON_INCLUDE_DIR})

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wpedantic")

add_custom_target(generate_lib_version COMMAND ${CMAKE_COMMAND} -D SOURCE_FILE="${PROJECT_SOURCE_DIR}/include/${PROJECT_NAME}/version.h.in" -D DEST_FILE="${PROJECT_BINARY_DIR}/include/${PROJECT_NAME}/version.h" -D PROJECT_VERSION=${PROJECT_VERSION} -P ${PROJECT_SOURCE_DIR}/cmake/version.cmake)

add_library(${PROJECT_NAME} STATIC jwt.cpp utils.cpp json.cpp)
add_dependencies(${PROJECT_NAME} generate_lib_version)

install(TARGETS ${PROJECT_NAME} LIBRARY DESTINATION lib ARCHIVE DESTINATION lib RUNTIME DESTINATION bin)
install(DIRECTORY "${PROJECT_SOURCE_DIR}/include/${PROJECT_NAME}" DESTINATION include)
install(FILES "${PROJECT_BINARY_DIR}/include/${PROJECT_NAME}/version.h" DESTINATION "include/${PROJECT_NAME}")
