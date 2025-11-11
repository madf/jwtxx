cmake_minimum_required ( VERSION 3.5...4.1 )

set ( CMAKE_MODULE_PATH ${CMAKE_SOURCE_DIR}/cmake/modules )

project ( jwtxx VERSION 1.1.11 )

enable_language ( CXX )

set ( CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -W -Wall -Wextra -Wshadow -Wold-style-cast -Wnull-dereference -Wstrict-aliasing -pedantic" )

set ( CMAKE_CXX_STANDARD 11 )
set ( CMAKE_CXX_STANDARD_REQUIRED ON )
set ( CMAKE_CXX_EXTENSIONS OFF )

option ( BUILD_TOOL "Build jwttool utility." OFF )
option ( BUILD_TESTS "Build tests." OFF )
option ( BUILD_ALL "Build the lib, the tool and the tests." OFF )
option ( ENABLE_COVERAGE "Enable code coverage analysis." OFF )
option ( TIDY "Build with clang-tidy." OFF )
option ( IWYU "Build with include-what-you-use." OFF )

if ( BUILD_ALL )
    set ( BUILD_TOOL ON )
    set ( BUILD_TESTS ON )
endif ( BUILD_ALL )

if ( ENABLE_COVERAGE )
    # Check prereqs
    find_program( GCOV_PATH gcov )
    find_program( LCOV_PATH  NAMES lcov lcov.bat lcov.exe lcov.perl)
    find_program( GENHTML_PATH NAMES genhtml genhtml.perl genhtml.bat )
    find_program( GCOVR_PATH gcovr PATHS ${CMAKE_SOURCE_DIR}/scripts/test)
    find_program( SIMPLE_PYTHON_EXECUTABLE python )

    if ( NOT GCOV_PATH )
        message ( STATUS "Code coverage: gcov not found" )
    endif ( NOT GCOV_PATH )

    if ( NOT LCOV_PATH )
        message ( STATUS "Code coverage: lcov not found" )
    endif ( NOT LCOV_PATH )

    if ( NOT GENHTML_PATH )
        message ( STATUS "Code coverage: genhtml not found (part of lcov package)" )
    endif ( NOT GENHTML_PATH )

    if ( NOT GCOVR_PATH )
        message ( STATUS "Code coverage: gcovr not found" )
    endif (NOT GCOVR_PATH)

    if ( GCOV_PATH AND LCOV_PATH AND GENHTML_PATH AND GCOVR_PATH )
        message ( STATUS "Code coverage analysis enabled" )
        set ( CODE_COVERAGE_ENABLED ON )
        set ( BUILD_TESTS ON )
    else ( GCOV_PATH AND LCOV_PATH AND GENHTML_PATH AND GCOVR_PATH )
        message ( STATUS WARNING "Code coverage: missing required tools, will not generate code coverage report" )
        set ( CODE_COVERAGE_ENABLED OFF )
    endif ( GCOV_PATH AND LCOV_PATH AND GENHTML_PATH AND GCOVR_PATH )
endif ( ENABLE_COVERAGE )

if ( BUILD_TESTS )
    find_package ( Boost 1.46.0 REQUIRED COMPONENTS unit_test_framework )
endif ( BUILD_TESTS )

if ( CODE_COVERAGE_ENABLED )
    include ( CodeCoverage )
    APPEND_COVERAGE_COMPILER_FLAGS ()
endif ( CODE_COVERAGE_ENABLED )

if ( TIDY )
    find_program ( CLANG_TIDY_EXE NAMES "clang-tidy" DOC "Path to clang-tidy executable" )
    if ( NOT CLANG_TIDY_EXE )
        message ( STATUS "clang-tidy not found." )
    else ( NOT CLANG_TIDY_EXE )
        message ( STATUS "clang-tidy found: ${CLANG_TIDY_EXE}" )
        set ( DO_CLANG_TIDY "${CLANG_TIDY_EXE}" )
    endif ( NOT CLANG_TIDY_EXE )
endif ( TIDY )

if ( IWYU )
    find_program ( INCLUDE_WHAT_YOU_USE_EXE NAMES "include-what-you-use" DOC "Path to include-what-you-use executable" )
    if ( NOT INCLUDE_WHAT_YOU_USE_EXE )
        message ( STATUS "include-what-you-use not found." )
    else ( NOT INCLUDE_WHAT_YOU_USE_EXE )
        message ( STATUS "include-what-you-use found: ${INCLUDE_WHAT_YOU_USE_EXE}" )
        set ( DO_INCLUDE_WHAT_YOU_USE "${INCLUDE_WHAT_YOU_USE_EXE}" )
    endif ( NOT INCLUDE_WHAT_YOU_USE_EXE )
endif ( IWYU )

if ( APPLE )
    set ( OPENSSL_ROOT_DIR "/opt/local/" "/usr/local/opt/openssl/" )
endif ( APPLE )

find_package ( Jansson REQUIRED )

find_package ( OpenSSL 1.0.0 REQUIRED )

try_compile ( HAS_OVERRIDE_FEATURE ${CMAKE_CURRENT_BINARY_DIR} "${PROJECT_SOURCE_DIR}/checks/checkoverride.cpp" )
if ( NOT HAS_OVERRIDE_FEATURE )
    set ( CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Doverride=" )
endif ( NOT HAS_OVERRIDE_FEATURE )

try_compile ( CONST_BIO_NEW_MEM_BUF ${CMAKE_CURRENT_BINARY_DIR} "${PROJECT_SOURCE_DIR}/checks/openssl_bio_new_mem_buf.cpp" LINK_LIBRARIES ${OPENSSL_LIBRARIES} )
if ( CONST_BIO_NEW_MEM_BUF )
    set ( CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -DCONST_BIO_NEW_MEM_BUF" )
    message ( STATUS "The first parameter of the BIO_new_mem_buf is const." )
else ( CONST_BIO_NEW_MEM_BUF )
    message ( STATUS "The first parameter of the BIO_new_mem_buf is non-const." )
endif ( CONST_BIO_NEW_MEM_BUF )

set (CPACK_PACKAGE_NAME ${PROJECT_NAME})
set (CPACK_PACKAGE_VERSION ${PROJECT_VERSION})

add_subdirectory ( include )
add_subdirectory ( src )

if ( BUILD_TOOL )
    add_subdirectory ( tools )
endif ( BUILD_TOOL )

if ( BUILD_TESTS )
    enable_testing ()
    add_subdirectory ( tests )
endif ( BUILD_TESTS )

add_custom_target ( cppcheck COMMAND cppcheck --enable=all --std=c++11 -I ${jwtxx_SOURCE_DIR}/include ${jwtxx_SOURCE_DIR}/src ${jwtxx_SOURCE_DIR}/tools )

include (CPack)
