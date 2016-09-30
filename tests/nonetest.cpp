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

BOOST_AUTO_TEST_CASE(TestVerifier)
{
    BOOST_CHECK(JWTXX::JWT::verify("eyJ0eXAiOiJKV1QiLCJhbGciOiJub25lIn0.eyJpc3MiOiJtYWRmIn0", JWTXX::Key(JWTXX::Algorithm::none, "")));
    BOOST_CHECK(JWTXX::JWT::verify("eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJpc3MiOiJtYWRmIiwic3ViIjoidXNlciIsIm5iZiI6MTQ3NTI0MDY0NiwiZXhwIjoxNDc1MjQ0MjQ2LCJpYXQiOjE0NzUyNDA2NDZ9", JWTXX::Key(JWTXX::Algorithm::none, ""), {JWTXX::Validate::exp(1475244245)}));
    BOOST_CHECK(!JWTXX::JWT::verify("eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJpc3MiOiJtYWRmIiwic3ViIjoidXNlciIsIm5iZiI6MTQ3NTI0MDY0NiwiZXhwIjoxNDc1MjQ0MjQ2LCJpYXQiOjE0NzUyNDA2NDZ9", JWTXX::Key(JWTXX::Algorithm::none, ""), {JWTXX::Validate::exp(1475244247)}));
    BOOST_CHECK(!JWTXX::JWT::verify("eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJpc3MiOiJtYWRmIiwic3ViIjoidXNlciIsIm5iZiI6MTQ3NTI0MDY0NiwiZXhwIjoxNDc1MjQ0MjQ2LCJpYXQiOjE0NzUyNDA2NDZ9", JWTXX::Key(JWTXX::Algorithm::none, ""), {JWTXX::Validate::iat(1475240645)}));
    BOOST_CHECK(JWTXX::JWT::verify("eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJpc3MiOiJtYWRmIiwic3ViIjoidXNlciIsIm5iZiI6MTQ3NTI0MDY0NiwiZXhwIjoxNDc1MjQ0MjQ2LCJpYXQiOjE0NzUyNDA2NDZ9", JWTXX::Key(JWTXX::Algorithm::none, ""), {JWTXX::Validate::iat(1475240647)}));
    BOOST_CHECK(!JWTXX::JWT::verify("eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJpc3MiOiJtYWRmIiwic3ViIjoidXNlciIsIm5iZiI6MTQ3NTI0MDY0NiwiZXhwIjoxNDc1MjQ0MjQ2LCJpYXQiOjE0NzUyNDA2NDZ9", JWTXX::Key(JWTXX::Algorithm::none, ""), {JWTXX::Validate::nbf(1475240645)}));
    BOOST_CHECK(JWTXX::JWT::verify("eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJpc3MiOiJtYWRmIiwic3ViIjoidXNlciIsIm5iZiI6MTQ3NTI0MDY0NiwiZXhwIjoxNDc1MjQ0MjQ2LCJpYXQiOjE0NzUyNDA2NDZ9", JWTXX::Key(JWTXX::Algorithm::none, ""), {JWTXX::Validate::nbf(1475240647)}));
    BOOST_CHECK(JWTXX::JWT::verify("eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJpc3MiOiJtYWRmIiwic3ViIjoidXNlciIsIm5iZiI6MTQ3NTI0MDY0NiwiZXhwIjoxNDc1MjQ0MjQ2LCJpYXQiOjE0NzUyNDA2NDZ9", JWTXX::Key(JWTXX::Algorithm::none, ""), {JWTXX::Validate::exp(1475244245), JWTXX::Validate::iat(1475244245), JWTXX::Validate::nbf(1475244245)}));
    BOOST_CHECK(!JWTXX::JWT::verify("eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJpc3MiOiJtYWRmIiwic3ViIjoidXNlciIsIm5iZiI6MTQ3NTI0MDY0NiwiZXhwIjoxNDc1MjQ0MjQ2LCJpYXQiOjE0NzUyNDA2NDZ9", JWTXX::Key(JWTXX::Algorithm::none, ""), {JWTXX::Validate::exp(1475244247), JWTXX::Validate::iat(1475244247), JWTXX::Validate::nbf(1475244247)}));
    BOOST_CHECK(!JWTXX::JWT::verify("eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJpc3MiOiJtYWRmIiwic3ViIjoidXNlciIsIm5iZiI6MTQ3NTI0MDY0NiwiZXhwIjoxNDc1MjQ0MjQ2LCJpYXQiOjE0NzUyNDA2NDZ9", JWTXX::Key(JWTXX::Algorithm::none, ""), {JWTXX::Validate::exp(1475240645), JWTXX::Validate::iat(1475240645), JWTXX::Validate::nbf(1475240645)}));
    BOOST_CHECK(JWTXX::JWT::verify("eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJpc3MiOiJtYWRmIiwic3ViIjoidXNlciIsIm5iZiI6MTQ3NTI0MDY0NiwiZXhwIjoxNDc1MjQ0MjQ2LCJpYXQiOjE0NzUyNDA2NDZ9", JWTXX::Key(JWTXX::Algorithm::none, ""), {JWTXX::Validate::iss("madf")}));
    BOOST_CHECK(!JWTXX::JWT::verify("eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJpc3MiOiJtYWRmIiwic3ViIjoidXNlciIsIm5iZiI6MTQ3NTI0MDY0NiwiZXhwIjoxNDc1MjQ0MjQ2LCJpYXQiOjE0NzUyNDA2NDZ9", JWTXX::Key(JWTXX::Algorithm::none, ""), {JWTXX::Validate::iss("somebody")}));
    BOOST_CHECK(JWTXX::JWT::verify("eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJpc3MiOiJtYWRmIiwic3ViIjoidXNlciIsIm5iZiI6MTQ3NTI0MDY0NiwiZXhwIjoxNDc1MjQ0MjQ2LCJpYXQiOjE0NzUyNDA2NDZ9", JWTXX::Key(JWTXX::Algorithm::none, ""), {JWTXX::Validate::sub("user")}));
    BOOST_CHECK(!JWTXX::JWT::verify("eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJpc3MiOiJtYWRmIiwic3ViIjoidXNlciIsIm5iZiI6MTQ3NTI0MDY0NiwiZXhwIjoxNDc1MjQ0MjQ2LCJpYXQiOjE0NzUyNDA2NDZ9", JWTXX::Key(JWTXX::Algorithm::none, ""), {JWTXX::Validate::sub("someone")}));
    BOOST_CHECK(JWTXX::JWT::verify("eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJpc3MiOiJtYWRmIiwic3ViIjoidXNlciIsIm5iZiI6MTQ3NTI0MDY0NiwiZXhwIjoxNDc1MjQ0MjQ2LCJpYXQiOjE0NzUyNDA2NDZ9", JWTXX::Key(JWTXX::Algorithm::none, ""), {JWTXX::Validate::aud("")}));
    BOOST_CHECK(JWTXX::JWT::verify("eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJpc3MiOiJtYWRmIiwic3ViIjoidXNlciIsIm5iZiI6MTQ3NTI0MDY0NiwiZXhwIjoxNDc1MjQ0MjQ2LCJpYXQiOjE0NzUyNDA2NDZ9", JWTXX::Key(JWTXX::Algorithm::none, ""), {JWTXX::Validate::aud("something")})); // Audience is missing in the token
}

BOOST_AUTO_TEST_CASE(TestParserNoVerify)
{
    auto jwt = JWTXX::JWT::parse("eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJpc3MiOiJtYWRmIiwic3ViIjoidXNlciIsIm5iZiI6MTQ3NTI0MDY0NiwiZXhwIjoxNDc1MjQ0MjQ2LCJpYXQiOjE0NzUyNDA2NDZ9");
    BOOST_CHECK_EQUAL(jwt.alg(), JWTXX::Algorithm::none);
    BOOST_CHECK_EQUAL(jwt.claim("iss"), "madf");
    BOOST_CHECK_EQUAL(jwt.claim("sub"), "user");
    BOOST_CHECK_EQUAL(jwt.claim("exp"), "1475244246");
    BOOST_CHECK_EQUAL(jwt.claim("iat"), "1475240646");
    BOOST_CHECK_EQUAL(jwt.claim("nbf"), "1475240646");
}

BOOST_AUTO_TEST_CASE(TestParserExtraVerification)
{
    JWTXX::JWT jwt("eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJpc3MiOiJtYWRmIiwic3ViIjoidXNlciIsIm5iZiI6MTQ3NTI0MDY0NiwiZXhwIjoxNDc1MjQ0MjQ2LCJpYXQiOjE0NzUyNDA2NDZ9", JWTXX::Key(JWTXX::Algorithm::none, ""), {JWTXX::Validate::exp(1475244245), JWTXX::Validate::iat(1475244245), JWTXX::Validate::nbf(1475244245)});
    BOOST_CHECK_EQUAL(jwt.alg(), JWTXX::Algorithm::none);
    BOOST_CHECK_EQUAL(jwt.claim("iss"), "madf");
    BOOST_CHECK_EQUAL(jwt.claim("sub"), "user");
    BOOST_CHECK_EQUAL(jwt.claim("exp"), "1475244246");
    BOOST_CHECK_EQUAL(jwt.claim("iat"), "1475240646");
    BOOST_CHECK_EQUAL(jwt.claim("nbf"), "1475240646");
    BOOST_CHECK_THROW(JWTXX::JWT("eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJpc3MiOiJtYWRmIiwic3ViIjoidXNlciIsIm5iZiI6MTQ3NTI0MDY0NiwiZXhwIjoxNDc1MjQ0MjQ2LCJpYXQiOjE0NzUyNDA2NDZ9", JWTXX::Key(JWTXX::Algorithm::none, ""), {JWTXX::Validate::exp(1475244247), JWTXX::Validate::iat(1475244247), JWTXX::Validate::nbf(1475244247)}), JWTXX::JWT::Error);
    BOOST_CHECK_THROW(JWTXX::JWT("eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJpc3MiOiJtYWRmIiwic3ViIjoidXNlciIsIm5iZiI6MTQ3NTI0MDY0NiwiZXhwIjoxNDc1MjQ0MjQ2LCJpYXQiOjE0NzUyNDA2NDZ9", JWTXX::Key(JWTXX::Algorithm::none, ""), {JWTXX::Validate::exp(1475240645), JWTXX::Validate::iat(1475240645), JWTXX::Validate::nbf(1475240645)}), JWTXX::JWT::Error);
}
