add_library ( ${PROJECT_NAME} STATIC jwt.cpp utils.cpp json.cpp )

target_include_directories ( ${PROJECT_NAME} PUBLIC ${PROJECT_SOURCE_DIR}/include PRIVATE ${PROJECT_BINARY_DIR}/include)
target_link_libraries ( ${PROJECT_NAME} PRIVATE Jansson::Jansson OpenSSL::Crypto )

set ( INCLUDE_PREFIX "${PROJECT_SOURCE_DIR}/include/${PROJECT_NAME}" )

install ( TARGETS ${PROJECT_NAME} LIBRARY DESTINATION lib ARCHIVE DESTINATION lib RUNTIME DESTINATION bin )
install ( FILES "${INCLUDE_PREFIX}/jwt.h" DESTINATION "include/${PROJECT_NAME}" )
install ( FILES "${INCLUDE_PREFIX}/ios.h" DESTINATION "include/${PROJECT_NAME}" )
install ( FILES "${PROJECT_BINARY_DIR}/include/${PROJECT_NAME}/version.h" DESTINATION "include/${PROJECT_NAME}" )
