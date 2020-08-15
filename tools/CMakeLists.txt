project ( jwttool VERSION 1.0.2 )

find_package ( Threads REQUIRED )

set ( THREADS_PREFER_PTHREAD_FLAG ON )

set_source_files_properties ( toolversion.h PROPERTIES GENERATED TRUE )

configure_file ( toolversion.h.in toolversion.h ESCAPE_QUOTES @ONLY )

add_executable ( ${PROJECT_NAME} jwttool.cpp )
target_include_directories ( ${PROJECT_NAME} PRIVATE ${PROJECT_BINARY_DIR} ${jwtxx_SOURCE_DIR}/src ${jwtxx_BINARY_DIR}/include )
target_link_libraries ( ${PROJECT_NAME} jwtxx Jansson::Jansson OpenSSL::Crypto dl Threads::Threads )

if ( CLANG_TIDY_EXE )
    set_target_properties ( ${PROJECT_NAME} PROPERTIES CXX_CLANG_TIDY "${DO_CLANG_TIDY}" )
endif ( CLANG_TIDY_EXE )

if ( INCLUDE_WHAT_YOU_USE_EXE )
    set_target_properties ( ${PROJECT_NAME} PROPERTIES CXX_INCLUDE_WHAT_YOU_USE "${DO_INCLUDE_WHAT_YOU_USE}" )
endif ( INCLUDE_WHAT_YOU_USE_EXE )

install ( TARGETS ${PROJECT_NAME} RUNTIME DESTINATION bin )
