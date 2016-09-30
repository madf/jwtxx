#include "jwtxx/jwt.h"
#include "jwtxx/ios.h"

#include "initopenssl.h"

#define BOOST_TEST_MODULE JWTHMACAlgTest

#include <boost/test/included/unit_test.hpp>

BOOST_GLOBAL_FIXTURE(InitOpenSSL)

BOOST_AUTO_TEST_CASE(TestCtor256)
{
    JWTXX::JWT jwt(JWTXX::Algorithm::HS256, {{"iss", "madf"}});

    BOOST_CHECK_EQUAL(jwt.alg(), JWTXX::Algorithm::HS256);
    BOOST_CHECK(!jwt.claims().empty());
    BOOST_CHECK(!jwt.header().empty());
    auto header = jwt.header();
    BOOST_CHECK_EQUAL(header["alg"], "HS256");
    BOOST_CHECK_EQUAL(header["typ"], "JWT");
    BOOST_CHECK_EQUAL(jwt.claim("iss"), "madf");
    auto token = jwt.token("secret-key");
    // Jansson uses hashtables form JSON objects and hash function implementation reads over the boundary of the string, yet word-aligned, so actual order of header fields and claims is undefined.
    BOOST_CHECK(token == "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJtYWRmIn0.vIkGeF48t56EoWPeFUfd8fBddpS4GXtmA3K8Gs8W_6o" || token == "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJtYWRmIn0.JJvVBkQMTjGaQGiuE8YZ4PKYV5pTDE5NsPgOe3-ifw4");
}

BOOST_AUTO_TEST_CASE(TestCtor384)
{
    JWTXX::JWT jwt(JWTXX::Algorithm::HS384, {{"iss", "madf"}});

    BOOST_CHECK_EQUAL(jwt.alg(), JWTXX::Algorithm::HS384);
    BOOST_CHECK(!jwt.claims().empty());
    BOOST_CHECK(!jwt.header().empty());
    auto header = jwt.header();
    BOOST_CHECK_EQUAL(header["alg"], "HS384");
    BOOST_CHECK_EQUAL(header["typ"], "JWT");
    BOOST_CHECK_EQUAL(jwt.claim("iss"), "madf");
    auto token = jwt.token("secret-key");
    // Jansson uses hashtables form JSON objects and hash function implementation reads over the boundary of the string, yet word-aligned, so actual order of header fields and claims is undefined.
    BOOST_CHECK(token == "eyJhbGciOiJIUzM4NCIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJtYWRmIn0.oK6EMpKrAUGhQTvW6cd1LzO0RgMn_6BhJjy6jtSvkE3wies7LX3tRaHiPZDNnIMR" || token == "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzM4NCJ9.eyJpc3MiOiJtYWRmIn0.iQjt_e34Vti6ljweso9Vz4ajyujHlvrNhFiGt8y45gOsEQ80bNS5F3YtVkC570TY");
}

BOOST_AUTO_TEST_CASE(TestCtor512)
{
    JWTXX::JWT jwt(JWTXX::Algorithm::HS512, {{"iss", "madf"}});

    BOOST_CHECK_EQUAL(jwt.alg(), JWTXX::Algorithm::HS512);
    BOOST_CHECK(!jwt.claims().empty());
    BOOST_CHECK(!jwt.header().empty());
    auto header = jwt.header();
    BOOST_CHECK_EQUAL(header["alg"], "HS512");
    BOOST_CHECK_EQUAL(header["typ"], "JWT");
    BOOST_CHECK_EQUAL(jwt.claim("iss"), "madf");
    auto token = jwt.token("secret-key");
    // Jansson uses hashtables form JSON objects and hash function implementation reads over the boundary of the string, yet word-aligned, so actual order of header fields and claims is undefined.
    BOOST_CHECK(token == "eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJtYWRmIn0.I9H7VuaKsVIyYMRCIkl3YY0niNR5D9wnloF3jCfI7_f0Md4cr20tj2kV7tV5hrNMoTbSTP4SZM6AcfN4xCfvYg" || token == "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzUxMiJ9.eyJpc3MiOiJtYWRmIn0._iBZ2gZQsv5v2f8mZHKf45zUYYdCurzCyCf6UvRHGaOJTFUqJBMpL4UzZafnWQ9p27oAXgEgzlHyc0fWDydwKw");
}

BOOST_AUTO_TEST_CASE(TestParser256)
{
    JWTXX::JWT jwt("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJtYWRmIn0.vIkGeF48t56EoWPeFUfd8fBddpS4GXtmA3K8Gs8W_6o", JWTXX::Key(JWTXX::Algorithm::HS256, "secret-key"));

    BOOST_CHECK_EQUAL(jwt.alg(), JWTXX::Algorithm::HS256);
    BOOST_CHECK(!jwt.claims().empty());
    BOOST_CHECK(!jwt.header().empty());
    auto header = jwt.header();
    BOOST_CHECK_EQUAL(header["alg"], "HS256");
    BOOST_CHECK_EQUAL(header["typ"], "JWT");
    BOOST_CHECK_EQUAL(jwt.claim("iss"), "madf");
    auto token = jwt.token("secret-key");
    // Jansson uses hashtables form JSON objects and hash function implementation reads over the boundary of the string, yet word-aligned, so actual order of header fields and claims is undefined.
    BOOST_CHECK(token == "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJtYWRmIn0.vIkGeF48t56EoWPeFUfd8fBddpS4GXtmA3K8Gs8W_6o" || token == "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJtYWRmIn0.JJvVBkQMTjGaQGiuE8YZ4PKYV5pTDE5NsPgOe3-ifw4");
}

BOOST_AUTO_TEST_CASE(TestParserDifferentFieldOrder256)
{
    JWTXX::JWT jwt("eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJtYWRmIn0.JJvVBkQMTjGaQGiuE8YZ4PKYV5pTDE5NsPgOe3-ifw4", JWTXX::Key(JWTXX::Algorithm::HS256, "secret-key"));

    BOOST_CHECK_EQUAL(jwt.alg(), JWTXX::Algorithm::HS256);
    BOOST_CHECK(!jwt.claims().empty());
    BOOST_CHECK(!jwt.header().empty());
    auto header = jwt.header();
    BOOST_CHECK_EQUAL(header["alg"], "HS256");
    BOOST_CHECK_EQUAL(header["typ"], "JWT");
    BOOST_CHECK_EQUAL(jwt.claim("iss"), "madf");
    auto token = jwt.token("secret-key");
    // Jansson uses hashtables form JSON objects and hash function implementation reads over the boundary of the string, yet word-aligned, so actual order of header fields and claims is undefined.
    BOOST_CHECK(token == "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJtYWRmIn0.vIkGeF48t56EoWPeFUfd8fBddpS4GXtmA3K8Gs8W_6o" || token == "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJtYWRmIn0.JJvVBkQMTjGaQGiuE8YZ4PKYV5pTDE5NsPgOe3-ifw4");
}

BOOST_AUTO_TEST_CASE(TestParser384)
{
    JWTXX::JWT jwt("eyJhbGciOiJIUzM4NCIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJtYWRmIn0.oK6EMpKrAUGhQTvW6cd1LzO0RgMn_6BhJjy6jtSvkE3wies7LX3tRaHiPZDNnIMR", JWTXX::Key(JWTXX::Algorithm::HS384, "secret-key"));

    BOOST_CHECK_EQUAL(jwt.alg(), JWTXX::Algorithm::HS384);
    BOOST_CHECK(!jwt.claims().empty());
    BOOST_CHECK(!jwt.header().empty());
    auto header = jwt.header();
    BOOST_CHECK_EQUAL(header["alg"], "HS384");
    BOOST_CHECK_EQUAL(header["typ"], "JWT");
    BOOST_CHECK_EQUAL(jwt.claim("iss"), "madf");
    auto token = jwt.token("secret-key");
    // Jansson uses hashtables form JSON objects and hash function implementation reads over the boundary of the string, yet word-aligned, so actual order of header fields and claims is undefined.
    BOOST_CHECK(token == "eyJhbGciOiJIUzM4NCIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJtYWRmIn0.oK6EMpKrAUGhQTvW6cd1LzO0RgMn_6BhJjy6jtSvkE3wies7LX3tRaHiPZDNnIMR" || token == "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzM4NCJ9.eyJpc3MiOiJtYWRmIn0.iQjt_e34Vti6ljweso9Vz4ajyujHlvrNhFiGt8y45gOsEQ80bNS5F3YtVkC570TY");
}

BOOST_AUTO_TEST_CASE(TestParserDifferentFieldOrder384)
{
    JWTXX::JWT jwt("eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzM4NCJ9.eyJpc3MiOiJtYWRmIn0.iQjt_e34Vti6ljweso9Vz4ajyujHlvrNhFiGt8y45gOsEQ80bNS5F3YtVkC570TY", JWTXX::Key(JWTXX::Algorithm::HS384, "secret-key"));

    BOOST_CHECK_EQUAL(jwt.alg(), JWTXX::Algorithm::HS384);
    BOOST_CHECK(!jwt.claims().empty());
    BOOST_CHECK(!jwt.header().empty());
    auto header = jwt.header();
    BOOST_CHECK_EQUAL(header["alg"], "HS384");
    BOOST_CHECK_EQUAL(header["typ"], "JWT");
    BOOST_CHECK_EQUAL(jwt.claim("iss"), "madf");
    auto token = jwt.token("secret-key");
    // Jansson uses hashtables form JSON objects and hash function implementation reads over the boundary of the string, yet word-aligned, so actual order of header fields and claims is undefined.
    BOOST_CHECK(token == "eyJhbGciOiJIUzM4NCIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJtYWRmIn0.oK6EMpKrAUGhQTvW6cd1LzO0RgMn_6BhJjy6jtSvkE3wies7LX3tRaHiPZDNnIMR" || token == "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzM4NCJ9.eyJpc3MiOiJtYWRmIn0.iQjt_e34Vti6ljweso9Vz4ajyujHlvrNhFiGt8y45gOsEQ80bNS5F3YtVkC570TY");
}

BOOST_AUTO_TEST_CASE(TestParser512)
{
    JWTXX::JWT jwt("eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJtYWRmIn0.I9H7VuaKsVIyYMRCIkl3YY0niNR5D9wnloF3jCfI7_f0Md4cr20tj2kV7tV5hrNMoTbSTP4SZM6AcfN4xCfvYg", JWTXX::Key(JWTXX::Algorithm::HS512, "secret-key"));

    BOOST_CHECK_EQUAL(jwt.alg(), JWTXX::Algorithm::HS512);
    BOOST_CHECK(!jwt.claims().empty());
    BOOST_CHECK(!jwt.header().empty());
    auto header = jwt.header();
    BOOST_CHECK_EQUAL(header["alg"], "HS512");
    BOOST_CHECK_EQUAL(header["typ"], "JWT");
    BOOST_CHECK_EQUAL(jwt.claim("iss"), "madf");
    auto token = jwt.token("secret-key");
    // Jansson uses hashtables form JSON objects and hash function implementation reads over the boundary of the string, yet word-aligned, so actual order of header fields and claims is undefined.
    BOOST_CHECK(token == "eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJtYWRmIn0.I9H7VuaKsVIyYMRCIkl3YY0niNR5D9wnloF3jCfI7_f0Md4cr20tj2kV7tV5hrNMoTbSTP4SZM6AcfN4xCfvYg" || token == "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzUxMiJ9.eyJpc3MiOiJtYWRmIn0._iBZ2gZQsv5v2f8mZHKf45zUYYdCurzCyCf6UvRHGaOJTFUqJBMpL4UzZafnWQ9p27oAXgEgzlHyc0fWDydwKw");
}

BOOST_AUTO_TEST_CASE(TestParserDifferentFieldOrder512)
{
    JWTXX::JWT jwt("eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzUxMiJ9.eyJpc3MiOiJtYWRmIn0._iBZ2gZQsv5v2f8mZHKf45zUYYdCurzCyCf6UvRHGaOJTFUqJBMpL4UzZafnWQ9p27oAXgEgzlHyc0fWDydwKw", JWTXX::Key(JWTXX::Algorithm::HS512, "secret-key"));

    BOOST_CHECK_EQUAL(jwt.alg(), JWTXX::Algorithm::HS512);
    BOOST_CHECK(!jwt.claims().empty());
    BOOST_CHECK(!jwt.header().empty());
    auto header = jwt.header();
    BOOST_CHECK_EQUAL(header["alg"], "HS512");
    BOOST_CHECK_EQUAL(header["typ"], "JWT");
    BOOST_CHECK_EQUAL(jwt.claim("iss"), "madf");
    auto token = jwt.token("secret-key");
    // Jansson uses hashtables form JSON objects and hash function implementation reads over the boundary of the string, yet word-aligned, so actual order of header fields and claims is undefined.
    BOOST_CHECK(token == "eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJtYWRmIn0.I9H7VuaKsVIyYMRCIkl3YY0niNR5D9wnloF3jCfI7_f0Md4cr20tj2kV7tV5hrNMoTbSTP4SZM6AcfN4xCfvYg" || token == "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzUxMiJ9.eyJpc3MiOiJtYWRmIn0._iBZ2gZQsv5v2f8mZHKf45zUYYdCurzCyCf6UvRHGaOJTFUqJBMpL4UzZafnWQ9p27oAXgEgzlHyc0fWDydwKw");
}

BOOST_AUTO_TEST_CASE(TestVerifier)
{
    BOOST_CHECK(JWTXX::JWT::verify("eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzUxMiJ9.eyJpc3MiOiJtYWRmIn0._iBZ2gZQsv5v2f8mZHKf45zUYYdCurzCyCf6UvRHGaOJTFUqJBMpL4UzZafnWQ9p27oAXgEgzlHyc0fWDydwKw", JWTXX::Key(JWTXX::Algorithm::HS512, "secret-key")));
    BOOST_CHECK(JWTXX::JWT::verify("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJtYWRmIiwic3ViIjoidXNlciIsIm5iZiI6MTQ3NTI0MjkyMywiZXhwIjoxNDc1MjQ2NTIzLCJpYXQiOjE0NzUyNDI5MjN9.C2ifmz5X6Z_8HsPM-d_5pSFG03IUAB_6c1CTTrsPQtc", JWTXX::Key(JWTXX::Algorithm::HS256, "secret-key"), {JWTXX::Validate::exp(1475246522)}));
    BOOST_CHECK(!JWTXX::JWT::verify("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJtYWRmIiwic3ViIjoidXNlciIsIm5iZiI6MTQ3NTI0MjkyMywiZXhwIjoxNDc1MjQ2NTIzLCJpYXQiOjE0NzUyNDI5MjN9.C2ifmz5X6Z_8HsPM-d_5pSFG03IUAB_6c1CTTrsPQtc", JWTXX::Key(JWTXX::Algorithm::HS256, "secret-key"), {JWTXX::Validate::exp(1475246524)}));
    BOOST_CHECK(!JWTXX::JWT::verify("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJtYWRmIiwic3ViIjoidXNlciIsIm5iZiI6MTQ3NTI0MjkyMywiZXhwIjoxNDc1MjQ2NTIzLCJpYXQiOjE0NzUyNDI5MjN9.C2ifmz5X6Z_8HsPM-d_5pSFG03IUAB_6c1CTTrsPQtc", JWTXX::Key(JWTXX::Algorithm::HS256, "secret-key"), {JWTXX::Validate::iat(1475242922)}));
    BOOST_CHECK(JWTXX::JWT::verify("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJtYWRmIiwic3ViIjoidXNlciIsIm5iZiI6MTQ3NTI0MjkyMywiZXhwIjoxNDc1MjQ2NTIzLCJpYXQiOjE0NzUyNDI5MjN9.C2ifmz5X6Z_8HsPM-d_5pSFG03IUAB_6c1CTTrsPQtc", JWTXX::Key(JWTXX::Algorithm::HS256, "secret-key"), {JWTXX::Validate::iat(1475242924)}));
    BOOST_CHECK(!JWTXX::JWT::verify("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJtYWRmIiwic3ViIjoidXNlciIsIm5iZiI6MTQ3NTI0MjkyMywiZXhwIjoxNDc1MjQ2NTIzLCJpYXQiOjE0NzUyNDI5MjN9.C2ifmz5X6Z_8HsPM-d_5pSFG03IUAB_6c1CTTrsPQtc", JWTXX::Key(JWTXX::Algorithm::HS256, "secret-key"), {JWTXX::Validate::nbf(1475242922)}));
    BOOST_CHECK(JWTXX::JWT::verify("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJtYWRmIiwic3ViIjoidXNlciIsIm5iZiI6MTQ3NTI0MjkyMywiZXhwIjoxNDc1MjQ2NTIzLCJpYXQiOjE0NzUyNDI5MjN9.C2ifmz5X6Z_8HsPM-d_5pSFG03IUAB_6c1CTTrsPQtc", JWTXX::Key(JWTXX::Algorithm::HS256, "secret-key"), {JWTXX::Validate::nbf(1475242924)}));
    BOOST_CHECK(JWTXX::JWT::verify("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJtYWRmIiwic3ViIjoidXNlciIsIm5iZiI6MTQ3NTI0MjkyMywiZXhwIjoxNDc1MjQ2NTIzLCJpYXQiOjE0NzUyNDI5MjN9.C2ifmz5X6Z_8HsPM-d_5pSFG03IUAB_6c1CTTrsPQtc", JWTXX::Key(JWTXX::Algorithm::HS256, "secret-key"), {JWTXX::Validate::exp(1475246522), JWTXX::Validate::iat(1475246522), JWTXX::Validate::nbf(1475246522)}));
    BOOST_CHECK(!JWTXX::JWT::verify("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJtYWRmIiwic3ViIjoidXNlciIsIm5iZiI6MTQ3NTI0MjkyMywiZXhwIjoxNDc1MjQ2NTIzLCJpYXQiOjE0NzUyNDI5MjN9.C2ifmz5X6Z_8HsPM-d_5pSFG03IUAB_6c1CTTrsPQtc", JWTXX::Key(JWTXX::Algorithm::HS256, "secret-key"), {JWTXX::Validate::exp(1475246524), JWTXX::Validate::iat(1475246524), JWTXX::Validate::nbf(1475246524)}));
    BOOST_CHECK(!JWTXX::JWT::verify("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJtYWRmIiwic3ViIjoidXNlciIsIm5iZiI6MTQ3NTI0MjkyMywiZXhwIjoxNDc1MjQ2NTIzLCJpYXQiOjE0NzUyNDI5MjN9.C2ifmz5X6Z_8HsPM-d_5pSFG03IUAB_6c1CTTrsPQtc", JWTXX::Key(JWTXX::Algorithm::HS256, "secret-key"), {JWTXX::Validate::exp(1475242922), JWTXX::Validate::iat(1475242922), JWTXX::Validate::nbf(1475242922)}));
    BOOST_CHECK(JWTXX::JWT::verify("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJtYWRmIiwic3ViIjoidXNlciIsIm5iZiI6MTQ3NTI0MjkyMywiZXhwIjoxNDc1MjQ2NTIzLCJpYXQiOjE0NzUyNDI5MjN9.C2ifmz5X6Z_8HsPM-d_5pSFG03IUAB_6c1CTTrsPQtc", JWTXX::Key(JWTXX::Algorithm::HS256, "secret-key"), {JWTXX::Validate::iss("madf")}));
    BOOST_CHECK(!JWTXX::JWT::verify("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJtYWRmIiwic3ViIjoidXNlciIsIm5iZiI6MTQ3NTI0MjkyMywiZXhwIjoxNDc1MjQ2NTIzLCJpYXQiOjE0NzUyNDI5MjN9.C2ifmz5X6Z_8HsPM-d_5pSFG03IUAB_6c1CTTrsPQtc", JWTXX::Key(JWTXX::Algorithm::HS256, "secret-key"), {JWTXX::Validate::iss("somebody")}));
    BOOST_CHECK(JWTXX::JWT::verify("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJtYWRmIiwic3ViIjoidXNlciIsIm5iZiI6MTQ3NTI0MjkyMywiZXhwIjoxNDc1MjQ2NTIzLCJpYXQiOjE0NzUyNDI5MjN9.C2ifmz5X6Z_8HsPM-d_5pSFG03IUAB_6c1CTTrsPQtc", JWTXX::Key(JWTXX::Algorithm::HS256, "secret-key"), {JWTXX::Validate::sub("user")}));
    BOOST_CHECK(!JWTXX::JWT::verify("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJtYWRmIiwic3ViIjoidXNlciIsIm5iZiI6MTQ3NTI0MjkyMywiZXhwIjoxNDc1MjQ2NTIzLCJpYXQiOjE0NzUyNDI5MjN9.C2ifmz5X6Z_8HsPM-d_5pSFG03IUAB_6c1CTTrsPQtc", JWTXX::Key(JWTXX::Algorithm::HS256, "secret-key"), {JWTXX::Validate::sub("someone")}));
    BOOST_CHECK(JWTXX::JWT::verify("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJtYWRmIiwic3ViIjoidXNlciIsIm5iZiI6MTQ3NTI0MjkyMywiZXhwIjoxNDc1MjQ2NTIzLCJpYXQiOjE0NzUyNDI5MjN9.C2ifmz5X6Z_8HsPM-d_5pSFG03IUAB_6c1CTTrsPQtc", JWTXX::Key(JWTXX::Algorithm::HS256, "secret-key"), {JWTXX::Validate::aud("")}));
    BOOST_CHECK(JWTXX::JWT::verify("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJtYWRmIiwic3ViIjoidXNlciIsIm5iZiI6MTQ3NTI0MjkyMywiZXhwIjoxNDc1MjQ2NTIzLCJpYXQiOjE0NzUyNDI5MjN9.C2ifmz5X6Z_8HsPM-d_5pSFG03IUAB_6c1CTTrsPQtc", JWTXX::Key(JWTXX::Algorithm::HS256, "secret-key"), {JWTXX::Validate::aud("something")})); // Audience is missing in the token
}

BOOST_AUTO_TEST_CASE(TestParserNoVerify)
{
    auto jwt = JWTXX::JWT::parse("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJtYWRmIiwic3ViIjoidXNlciIsIm5iZiI6MTQ3NTI0MjkyMywiZXhwIjoxNDc1MjQ2NTIzLCJpYXQiOjE0NzUyNDI5MjN9.C2ifmz5X6Z_8HsPM-d_5pSFG03IUAB_6c1CTTrsPQtc");
    BOOST_CHECK_EQUAL(jwt.alg(), JWTXX::Algorithm::HS256);
    BOOST_CHECK_EQUAL(jwt.claim("iss"), "madf");
    BOOST_CHECK_EQUAL(jwt.claim("sub"), "user");
    BOOST_CHECK_EQUAL(jwt.claim("exp"), "1475246523");
    BOOST_CHECK_EQUAL(jwt.claim("iat"), "1475242923");
    BOOST_CHECK_EQUAL(jwt.claim("nbf"), "1475242923");
}

BOOST_AUTO_TEST_CASE(TestParserNoVerifyCorruptedSignature)
{
    auto jwt = JWTXX::JWT::parse("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJtYWRmIiwic3ViIjoidXNlciIsIm5iZiI6MTQ3NTI0MjkyMywiZXhwIjoxNDc1MjQ2NTIzLCJpYXQiOjE0NzUyNDI5MjN9.C2ifmz5X6Z_8HsPM-d_5pSFG03IUAB_");
    BOOST_CHECK_EQUAL(jwt.alg(), JWTXX::Algorithm::HS256);
    BOOST_CHECK_EQUAL(jwt.claim("iss"), "madf");
    BOOST_CHECK_EQUAL(jwt.claim("sub"), "user");
    BOOST_CHECK_EQUAL(jwt.claim("exp"), "1475246523");
    BOOST_CHECK_EQUAL(jwt.claim("iat"), "1475242923");
    BOOST_CHECK_EQUAL(jwt.claim("nbf"), "1475242923");
}

BOOST_AUTO_TEST_CASE(TestParserExtraVerification)
{
    JWTXX::JWT jwt("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJtYWRmIiwic3ViIjoidXNlciIsIm5iZiI6MTQ3NTI0MjkyMywiZXhwIjoxNDc1MjQ2NTIzLCJpYXQiOjE0NzUyNDI5MjN9.C2ifmz5X6Z_8HsPM-d_5pSFG03IUAB_6c1CTTrsPQtc", JWTXX::Key(JWTXX::Algorithm::HS256, "secret-key"), {JWTXX::Validate::exp(1475246522), JWTXX::Validate::iat(1475246522), JWTXX::Validate::nbf(1475246522)});
    BOOST_CHECK_EQUAL(jwt.alg(), JWTXX::Algorithm::HS256);
    BOOST_CHECK_EQUAL(jwt.claim("iss"), "madf");
    BOOST_CHECK_EQUAL(jwt.claim("sub"), "user");
    BOOST_CHECK_EQUAL(jwt.claim("exp"), "1475246523");
    BOOST_CHECK_EQUAL(jwt.claim("iat"), "1475242923");
    BOOST_CHECK_EQUAL(jwt.claim("nbf"), "1475242923");
    BOOST_CHECK_THROW(JWTXX::JWT("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJtYWRmIiwic3ViIjoidXNlciIsIm5iZiI6MTQ3NTI0MjkyMywiZXhwIjoxNDc1MjQ2NTIzLCJpYXQiOjE0NzUyNDI5MjN9.C2ifmz5X6Z_8HsPM-d_5pSFG03IUAB_", JWTXX::Key(JWTXX::Algorithm::HS256, "secret-key")), JWTXX::JWT::Error);
    BOOST_CHECK_THROW(JWTXX::JWT("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJtYWRmIiwic3ViIjoidXNlciIsIm5iZiI6MTQ3NTI0MjkyMywiZXhwIjoxNDc1MjQ2NTIzLCJpYXQiOjE0NzUyNDI5MjN9.C2ifmz5X6Z_8HsPM-d_5pSFG03IUAB_6c1CTTrsPQtc", JWTXX::Key(JWTXX::Algorithm::HS256, "secret-key"), {JWTXX::Validate::exp(1475242922), JWTXX::Validate::iat(1475242922), JWTXX::Validate::nbf(1475242922)}), JWTXX::JWT::Error);
    BOOST_CHECK_THROW(JWTXX::JWT("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJtYWRmIiwic3ViIjoidXNlciIsIm5iZiI6MTQ3NTI0MjkyMywiZXhwIjoxNDc1MjQ2NTIzLCJpYXQiOjE0NzUyNDI5MjN9.C2ifmz5X6Z_8HsPM-d_5pSFG03IUAB_6c1CTTrsPQtc", JWTXX::Key(JWTXX::Algorithm::HS256, "secret-key"), {JWTXX::Validate::exp(1475246524), JWTXX::Validate::iat(1475246524), JWTXX::Validate::nbf(1475246524)}), JWTXX::JWT::Error);
}
