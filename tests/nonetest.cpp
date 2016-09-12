#include "jwtxx/jwt.h"
#include "jwtxx/ios.h"

#define BOOST_TEST_MODULE JWTNoneAlgTest

#include <boost/test/included/unit_test.hpp>

BOOST_AUTO_TEST_CASE(TestCtor)
{
    JWTXX::JWT jwt(JWTXX::Algorithm::none, {{"iss", "madf"}});

    BOOST_CHECK_EQUAL(jwt.alg(), JWTXX::Algorithm::none);
    BOOST_CHECK(!jwt.claims().empty());
    BOOST_CHECK(!jwt.header().empty());
    auto header = jwt.header();
    BOOST_CHECK_EQUAL(header["alg"], "none");
    BOOST_CHECK_EQUAL(header["typ"], "JWT");
    BOOST_CHECK_EQUAL(jwt.claim("iss"), "madf");
    BOOST_CHECK_EQUAL(jwt.token(""), "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJpc3MiOiJtYWRmIn0");
}

BOOST_AUTO_TEST_CASE(TestParser)
{
    JWTXX::JWT jwt("eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJpc3MiOiJtYWRmIn0", JWTXX::Key(JWTXX::Algorithm::none, ""));

    BOOST_CHECK_EQUAL(jwt.alg(), JWTXX::Algorithm::none);
    BOOST_CHECK(!jwt.claims().empty());
    BOOST_CHECK(!jwt.header().empty());
    auto header = jwt.header();
    BOOST_CHECK_EQUAL(header["alg"], "none");
    BOOST_CHECK_EQUAL(header["typ"], "JWT");
    BOOST_CHECK_EQUAL(jwt.claim("iss"), "madf");
    BOOST_CHECK_EQUAL(jwt.token(""), "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJpc3MiOiJtYWRmIn0");
}
