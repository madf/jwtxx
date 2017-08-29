include_directories(${PROJECT_SOURCE_DIR}/include)
include_directories(${PROJECT_BINARY_DIR}/include) # jwtxx/version.h

include_directories(${OPENSSL_INCLUDE_DIR})
include_directories(${JANSSON_INCLUDE_DIR})

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wpedantic")

add_custom_target(generate_lib_version COMMAND ${CMAKE_COMMAND} -D SOURCE_FILE="${PROJECT_SOURCE_DIR}/include/${PROJECT_NAME}/version.h.in" -D DEST_FILE="${PROJECT_BINARY_DIR}/include/${PROJECT_NAME}/version.h" -D PROJECT_VERSION=${PROJECT_VERSION} -P ${PROJECT_SOURCE_DIR}/cmake/version.cmake)

set(JWTXX_SRC_LIST json.cpp jwt.cpp utils.cpp)
set(JWTXX_INC_LIST base64url.h
                   hmackey.h
                   json.h
                   keyimpl.h
                   nonekey.h
                   pemkey.h
                   utils.h
                   ${PROJECT_SOURCE_DIR}/include/jwtxx/ios.h
                   ${PROJECT_SOURCE_DIR}/include/jwtxx/jwt.h
                   ${PROJECT_SOURCE_DIR}/include/jwtxx/version.h.in)

add_library(${PROJECT_NAME} STATIC ${JWTXX_SRC_LIST} ${JWTXX_INC_LIST})
add_dependencies(${PROJECT_NAME} generate_lib_version)

set(INCLUDE_PREFIX "${PROJECT_SOURCE_DIR}/include/${PROJECT_NAME}")

install(TARGETS ${PROJECT_NAME} LIBRARY DESTINATION lib ARCHIVE DESTINATION lib RUNTIME DESTINATION bin)
install(FILES "${INCLUDE_PREFIX}/jwt.h" DESTINATION "include/${PROJECT_NAME}")
install(FILES "${INCLUDE_PREFIX}/ios.h" DESTINATION "include/${PROJECT_NAME}")
install(FILES "${PROJECT_BINARY_DIR}/include/${PROJECT_NAME}/version.h" DESTINATION "include/${PROJECT_NAME}")
