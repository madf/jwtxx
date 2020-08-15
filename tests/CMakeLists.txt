find_package ( Threads REQUIRED )

set ( THREADS_PREFER_PTHREAD_FLAG ON )

set ( CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -Wno-unused-local-typedefs -Wno-unused-parameter" )

add_definitions ( -DBOOST_TEST_DYN_LINK )

add_executable ( nonetest nonetest.cpp )
target_link_libraries ( nonetest jwtxx Jansson::Jansson OpenSSL::Crypto Boost::unit_test_framework dl Threads::Threads )

add_executable ( hmactest hmactest.cpp )
target_link_libraries ( hmactest jwtxx Jansson::Jansson OpenSSL::Crypto Boost::unit_test_framework dl Threads::Threads )

add_executable ( rsatest rsatest.cpp )
target_link_libraries ( rsatest jwtxx Jansson::Jansson OpenSSL::Crypto Boost::unit_test_framework dl Threads::Threads )

add_executable ( ecdsatest ecdsatest.cpp )
target_link_libraries ( ecdsatest jwtxx Jansson::Jansson OpenSSL::Crypto Boost::unit_test_framework dl Threads::Threads )

add_test ( none nonetest )
add_test ( hmac hmactest )
add_test ( rsa rsatest )
add_test ( ecdsa ecdsatest )

configure_file ( rsa-2048-key-pair.pem rsa-2048-key-pair.pem COPYONLY )
configure_file ( rsa-2048-key-pair-pw.pem rsa-2048-key-pair-pw.pem COPYONLY )
configure_file ( public-rsa-2048-key.pem public-rsa-2048-key.pem COPYONLY )
configure_file ( ecdsa-256-key-pair.pem ecdsa-256-key-pair.pem COPYONLY )
configure_file ( ecdsa-256-key-pair-pw.pem ecdsa-256-key-pair-pw.pem COPYONLY )
configure_file ( public-ecdsa-256-key.pem public-ecdsa-256-key.pem COPYONLY )
configure_file ( rsa-cert.pem rsa-cert.pem COPYONLY )
configure_file ( ecdsa-cert.pem ecdsa-cert.pem COPYONLY )

if ( CODE_COVERAGE_ENABLED )
    set ( COVERAGE_EXCLUDES '${CMAKE_SOURCE_DIR}/tests/*' '*boost*' '/usr/*' )
    add_custom_target ( ctest COMMAND ${CMAKE_CTEST_COMMAND} )
    SETUP_TARGET_FOR_COVERAGE ( NAME all_coverage EXECUTABLE ctest -j ${PROCESSOR_COUNT} )
endif ( CODE_COVERAGE_ENABLED )
