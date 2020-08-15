add_library ( ${PROJECT_NAME} STATIC jwt.cpp utils.cpp json.cpp )

target_include_directories ( ${PROJECT_NAME} PUBLIC ${PROJECT_SOURCE_DIR}/include PRIVATE ${PROJECT_BINARY_DIR}/include)
target_link_libraries ( ${PROJECT_NAME} PRIVATE Jansson::Jansson OpenSSL::Crypto )

if ( CLANG_TIDY_EXE )
    set_target_properties ( ${PROJECT_NAME} PROPERTIES CXX_CLANG_TIDY "${DO_CLANG_TIDY}" )
endif ( CLANG_TIDY_EXE )

if ( INCLUDE_WHAT_YOU_USE_EXE )
    set_target_properties ( ${PROJECT_NAME} PROPERTIES CXX_INCLUDE_WHAT_YOU_USE "${DO_INCLUDE_WHAT_YOU_USE}" )
endif ( INCLUDE_WHAT_YOU_USE_EXE )

set ( INCLUDE_PREFIX "${PROJECT_SOURCE_DIR}/include/${PROJECT_NAME}" )

install ( TARGETS ${PROJECT_NAME} LIBRARY DESTINATION lib ARCHIVE DESTINATION lib RUNTIME DESTINATION bin )
install ( FILES "${INCLUDE_PREFIX}/jwt.h" DESTINATION "include/${PROJECT_NAME}" )
install ( FILES "${INCLUDE_PREFIX}/ios.h" DESTINATION "include/${PROJECT_NAME}" )
install ( FILES "${PROJECT_BINARY_DIR}/include/${PROJECT_NAME}/version.h" DESTINATION "include/${PROJECT_NAME}" )
