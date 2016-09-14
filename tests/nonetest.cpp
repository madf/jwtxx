#include "jwtxx/jwt.h"
#include "jwtxx/ios.h"

#include "initopenssl.h"

#define BOOST_TEST_MODULE JWTNoneAlgTest

#include <boost/test/included/unit_test.hpp>

BOOST_GLOBAL_FIXTURE(InitOpenSSL)

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
    auto token = jwt.token("");
    // Jansson uses hashtables form JSON objects and hash function implementation reads over the boundary of the string, yet word-aligned, so actual order of header fields and claims is undefined.
    BOOST_CHECK(token == "eyJ0eXAiOiJKV1QiLCJhbGciOiJub25lIn0.eyJpc3MiOiJtYWRmIn0" || token == "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJpc3MiOiJtYWRmIn0");
}

BOOST_AUTO_TEST_CASE(TestParser)
{
    JWTXX::JWT jwt("eyJ0eXAiOiJKV1QiLCJhbGciOiJub25lIn0.eyJpc3MiOiJtYWRmIn0", JWTXX::Key(JWTXX::Algorithm::none, ""));

    BOOST_CHECK_EQUAL(jwt.alg(), JWTXX::Algorithm::none);
    BOOST_CHECK(!jwt.claims().empty());
    BOOST_CHECK(!jwt.header().empty());
    auto header = jwt.header();
    BOOST_CHECK_EQUAL(header["alg"], "none");
    BOOST_CHECK_EQUAL(header["typ"], "JWT");
    BOOST_CHECK_EQUAL(jwt.claim("iss"), "madf");
    auto token = jwt.token("");
    // Jansson uses hashtables form JSON objects and hash function implementation reads over the boundary of the string, yet word-aligned, so actual order of header fields and claims is undefined.
    BOOST_CHECK(token == "eyJ0eXAiOiJKV1QiLCJhbGciOiJub25lIn0.eyJpc3MiOiJtYWRmIn0" || token == "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJpc3MiOiJtYWRmIn0");
}

BOOST_AUTO_TEST_CASE(TestParserDifferentFieldOrder)
{
    JWTXX::JWT jwt("eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJpc3MiOiJtYWRmIn0", JWTXX::Key(JWTXX::Algorithm::none, ""));

    BOOST_CHECK_EQUAL(jwt.alg(), JWTXX::Algorithm::none);
    BOOST_CHECK(!jwt.claims().empty());
    BOOST_CHECK(!jwt.header().empty());
    auto header = jwt.header();
    BOOST_CHECK_EQUAL(header["alg"], "none");
    BOOST_CHECK_EQUAL(header["typ"], "JWT");
    BOOST_CHECK_EQUAL(jwt.claim("iss"), "madf");
    auto token = jwt.token("");
    // Jansson uses hashtables form JSON objects and hash function implementation reads over the boundary of the string, yet word-aligned, so actual order of header fields and claims is undefined.
    BOOST_CHECK(token == "eyJ0eXAiOiJKV1QiLCJhbGciOiJub25lIn0.eyJpc3MiOiJtYWRmIn0" || token == "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJpc3MiOiJtYWRmIn0");
}
