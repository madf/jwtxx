#include "jwtxx/jwt.h"
#include "jwtxx/ios.h"

#include "initopenssl.h"

#define BOOST_TEST_MODULE JWTHMACAlgTest

#include <boost/test/unit_test.hpp>

using JWTXX::Value;

namespace
{

constexpr auto token256Order1 = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJtYWRmIn0.vIkGeF48t56EoWPeFUfd8fBddpS4GXtmA3K8Gs8W_6o";
constexpr auto token256Order2 = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJtYWRmIn0.JJvVBkQMTjGaQGiuE8YZ4PKYV5pTDE5NsPgOe3-ifw4";
constexpr auto token384Order1 = "eyJhbGciOiJIUzM4NCIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJtYWRmIn0.oK6EMpKrAUGhQTvW6cd1LzO0RgMn_6BhJjy6jtSvkE3wies7LX3tRaHiPZDNnIMR";
constexpr auto token384Order2 = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzM4NCJ9.eyJpc3MiOiJtYWRmIn0.iQjt_e34Vti6ljweso9Vz4ajyujHlvrNhFiGt8y45gOsEQ80bNS5F3YtVkC570TY";
constexpr auto token512Order1 = "eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJtYWRmIn0.I9H7VuaKsVIyYMRCIkl3YY0niNR5D9wnloF3jCfI7_f0Md4cr20tj2kV7tV5hrNMoTbSTP4SZM6AcfN4xCfvYg";
constexpr auto token512Order2 = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzUxMiJ9.eyJpc3MiOiJtYWRmIn0._iBZ2gZQsv5v2f8mZHKf45zUYYdCurzCyCf6UvRHGaOJTFUqJBMpL4UzZafnWQ9p27oAXgEgzlHyc0fWDydwKw";
constexpr auto tokenWithExp = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJtYWRmIiwic3ViIjoidXNlciIsIm5iZiI6MTQ3NTI0MjkyMywiZXhwIjoxNDc1MjQ2NTIzLCJpYXQiOjE0NzUyNDI5MjN9.C2ifmz5X6Z_8HsPM-d_5pSFG03IUAB_6c1CTTrsPQtc";
constexpr auto tokenCorruptedSign = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJtYWRmIiwic3ViIjoidXNlciIsIm5iZiI6MTQ3NTI0MjkyMywiZXhwIjoxNDc1MjQ2NTIzLCJpYXQiOjE0NzUyNDI5MjN9.C2ifmz5X6Z_8HsPM-d_5pSFG03IUAB_";
constexpr auto brokenTokenWithExp1 = "bGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJtYWRmIiwic3ViIjoidXNlciIsIm5iZiI6MTQ3NTI0MjkyMywiZXhwIjoxNDc1MjQ2NTIzLCJpYXQiOjE0NzUyNDI5MjN9.C2ifmz5X6Z_8HsPM-d_5pSFG03IUAB_6c1CTTrsPQtc";
constexpr auto brokenTokenWithExp2 = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.c3MiOiJtYWRmIiwic3ViIjoidXNlciIsIm5iZiI6MTQ3NTI0MjkyMywiZXhwIjoxNDc1MjQ2NTIzLCJpYXQiOjE0NzUyNDI5MjN9.C2ifmz5X6Z_8HsPM-d_5pSFG03IUAB_6c1CTTrsPQtc";
constexpr auto notAToken1 = "";
constexpr auto notAToken2 = "Hello, World!";
constexpr auto invalidHeaderToken = "eyJhbGciOiJIUzI1NyIsInR5cCI6IkpXIn0.eyJuYW1lIjoiZm9vIn0.X3VrL2rQCKvmytP56JcvYjlq7Dl3zmarGMQa5Qx51bM";

}

BOOST_GLOBAL_FIXTURE(InitOpenSSL);

BOOST_AUTO_TEST_CASE(TestCtor256)
{
    JWTXX::JWT jwt(JWTXX::Algorithm::HS256, {{"iss", Value("madf")}});

    BOOST_CHECK_EQUAL(jwt.alg(), JWTXX::Algorithm::HS256);
    BOOST_CHECK(!jwt.claims().empty());
    BOOST_CHECK(!jwt.header().empty());
    auto header = jwt.header();
    BOOST_CHECK_EQUAL(header["alg"].getString(), "HS256");
    BOOST_CHECK_EQUAL(header["typ"].getString(), "JWT");
    BOOST_CHECK_EQUAL(jwt.claim("iss").getString(), "madf");
    auto token = jwt.token("secret-key");
    // Jansson uses hashtables form JSON objects and hash function implementation reads over the boundary of the string, yet word-aligned, so actual order of header fields and claims is undefined.
    BOOST_CHECK(token == token256Order1 || token == token256Order2);
}

BOOST_AUTO_TEST_CASE(TestCtor384)
{
    JWTXX::JWT jwt(JWTXX::Algorithm::HS384, {{"iss", Value("madf")}});

    BOOST_CHECK_EQUAL(jwt.alg(), JWTXX::Algorithm::HS384);
    BOOST_CHECK(!jwt.claims().empty());
    BOOST_CHECK(!jwt.header().empty());
    auto header = jwt.header();
    BOOST_CHECK_EQUAL(header["alg"].getString(), "HS384");
    BOOST_CHECK_EQUAL(header["typ"].getString(), "JWT");
    BOOST_CHECK_EQUAL(jwt.claim("iss").getString(), "madf");
    auto token = jwt.token("secret-key");
    // Jansson uses hashtables form JSON objects and hash function implementation reads over the boundary of the string, yet word-aligned, so actual order of header fields and claims is undefined.
    BOOST_CHECK(token == token384Order1 || token == token384Order2);
}

BOOST_AUTO_TEST_CASE(TestCtor512)
{
    JWTXX::JWT jwt(JWTXX::Algorithm::HS512, {{"iss", Value("madf")}});

    BOOST_CHECK_EQUAL(jwt.alg(), JWTXX::Algorithm::HS512);
    BOOST_CHECK(!jwt.claims().empty());
    BOOST_CHECK(!jwt.header().empty());
    auto header = jwt.header();
    BOOST_CHECK_EQUAL(header["alg"].getString(), "HS512");
    BOOST_CHECK_EQUAL(header["typ"].getString(), "JWT");
    BOOST_CHECK_EQUAL(jwt.claim("iss").getString(), "madf");
    auto token = jwt.token("secret-key");
    // Jansson uses hashtables form JSON objects and hash function implementation reads over the boundary of the string, yet word-aligned, so actual order of header fields and claims is undefined.
    BOOST_CHECK(token == token512Order1 || token == token512Order2);
}

BOOST_AUTO_TEST_CASE(TestParser256)
{
    JWTXX::JWT jwt(token256Order1, JWTXX::Key(JWTXX::Algorithm::HS256, "secret-key"));

    BOOST_CHECK_EQUAL(jwt.alg(), JWTXX::Algorithm::HS256);
    BOOST_CHECK(!jwt.claims().empty());
    BOOST_CHECK(!jwt.header().empty());
    auto header = jwt.header();
    BOOST_CHECK_EQUAL(header["alg"].getString(), "HS256");
    BOOST_CHECK_EQUAL(header["typ"].getString(), "JWT");
    BOOST_CHECK_EQUAL(jwt.claim("iss").getString(), "madf");
    auto token = jwt.token("secret-key");
    // Jansson uses hashtables form JSON objects and hash function implementation reads over the boundary of the string, yet word-aligned, so actual order of header fields and claims is undefined.
    BOOST_CHECK(token == token256Order1 || token == token256Order2);
}

BOOST_AUTO_TEST_CASE(TestParserDifferentFieldOrder256)
{
    JWTXX::JWT jwt(token256Order2, JWTXX::Key(JWTXX::Algorithm::HS256, "secret-key"));

    BOOST_CHECK_EQUAL(jwt.alg(), JWTXX::Algorithm::HS256);
    BOOST_CHECK(!jwt.claims().empty());
    BOOST_CHECK(!jwt.header().empty());
    auto header = jwt.header();
    BOOST_CHECK_EQUAL(header["alg"].getString(), "HS256");
    BOOST_CHECK_EQUAL(header["typ"].getString(), "JWT");
    BOOST_CHECK_EQUAL(jwt.claim("iss").getString(), "madf");
    auto token = jwt.token("secret-key");
    // Jansson uses hashtables form JSON objects and hash function implementation reads over the boundary of the string, yet word-aligned, so actual order of header fields and claims is undefined.
    BOOST_CHECK(token == token256Order1 || token == token256Order2);
}

BOOST_AUTO_TEST_CASE(TestParser384)
{
    JWTXX::JWT jwt(token384Order1, JWTXX::Key(JWTXX::Algorithm::HS384, "secret-key"));

    BOOST_CHECK_EQUAL(jwt.alg(), JWTXX::Algorithm::HS384);
    BOOST_CHECK(!jwt.claims().empty());
    BOOST_CHECK(!jwt.header().empty());
    auto header = jwt.header();
    BOOST_CHECK_EQUAL(header["alg"].getString(), "HS384");
    BOOST_CHECK_EQUAL(header["typ"].getString(), "JWT");
    BOOST_CHECK_EQUAL(jwt.claim("iss").getString(), "madf");
    auto token = jwt.token("secret-key");
    // Jansson uses hashtables form JSON objects and hash function implementation reads over the boundary of the string, yet word-aligned, so actual order of header fields and claims is undefined.
    BOOST_CHECK(token == token384Order1 || token == token384Order2);
}

BOOST_AUTO_TEST_CASE(TestParserDifferentFieldOrder384)
{
    JWTXX::JWT jwt(token384Order2, JWTXX::Key(JWTXX::Algorithm::HS384, "secret-key"));

    BOOST_CHECK_EQUAL(jwt.alg(), JWTXX::Algorithm::HS384);
    BOOST_CHECK(!jwt.claims().empty());
    BOOST_CHECK(!jwt.header().empty());
    auto header = jwt.header();
    BOOST_CHECK_EQUAL(header["alg"].getString(), "HS384");
    BOOST_CHECK_EQUAL(header["typ"].getString(), "JWT");
    BOOST_CHECK_EQUAL(jwt.claim("iss").getString(), "madf");
    auto token = jwt.token("secret-key");
    // Jansson uses hashtables form JSON objects and hash function implementation reads over the boundary of the string, yet word-aligned, so actual order of header fields and claims is undefined.
    BOOST_CHECK(token == token384Order1 || token == token384Order2);
}

BOOST_AUTO_TEST_CASE(TestParser512)
{
    JWTXX::JWT jwt(token512Order1, JWTXX::Key(JWTXX::Algorithm::HS512, "secret-key"));

    BOOST_CHECK_EQUAL(jwt.alg(), JWTXX::Algorithm::HS512);
    BOOST_CHECK(!jwt.claims().empty());
    BOOST_CHECK(!jwt.header().empty());
    auto header = jwt.header();
    BOOST_CHECK_EQUAL(header["alg"].getString(), "HS512");
    BOOST_CHECK_EQUAL(header["typ"].getString(), "JWT");
    BOOST_CHECK_EQUAL(jwt.claim("iss").getString(), "madf");
    auto token = jwt.token("secret-key");
    // Jansson uses hashtables form JSON objects and hash function implementation reads over the boundary of the string, yet word-aligned, so actual order of header fields and claims is undefined.
    BOOST_CHECK(token == token512Order1 || token == token512Order2);
}

BOOST_AUTO_TEST_CASE(TestParserDifferentFieldOrder512)
{
    JWTXX::JWT jwt(token512Order2, JWTXX::Key(JWTXX::Algorithm::HS512, "secret-key"));

    BOOST_CHECK_EQUAL(jwt.alg(), JWTXX::Algorithm::HS512);
    BOOST_CHECK(!jwt.claims().empty());
    BOOST_CHECK(!jwt.header().empty());
    auto header = jwt.header();
    BOOST_CHECK_EQUAL(header["alg"].getString(), "HS512");
    BOOST_CHECK_EQUAL(header["typ"].getString(), "JWT");
    BOOST_CHECK_EQUAL(jwt.claim("iss").getString(), "madf");
    auto token = jwt.token("secret-key");
    // Jansson uses hashtables form JSON objects and hash function implementation reads over the boundary of the string, yet word-aligned, so actual order of header fields and claims is undefined.
    BOOST_CHECK(token == token512Order1 || token == token512Order2);
}

BOOST_AUTO_TEST_CASE(TestVerifier)
{
    BOOST_CHECK(JWTXX::JWT::verify(token512Order2, JWTXX::Key(JWTXX::Algorithm::HS512, "secret-key")));
    BOOST_CHECK(JWTXX::JWT::verify(tokenWithExp, JWTXX::Key(JWTXX::Algorithm::HS256, "secret-key"), {JWTXX::Validate::exp(1475246522)}));
    BOOST_CHECK(!JWTXX::JWT::verify(tokenWithExp, JWTXX::Key(JWTXX::Algorithm::HS256, "secret-key"), {JWTXX::Validate::exp(1475246524)}));
    BOOST_CHECK(!JWTXX::JWT::verify(tokenWithExp, JWTXX::Key(JWTXX::Algorithm::HS256, "secret-key"), {JWTXX::Validate::iat(1475242922)}));
    BOOST_CHECK(JWTXX::JWT::verify(tokenWithExp, JWTXX::Key(JWTXX::Algorithm::HS256, "secret-key"), {JWTXX::Validate::iat(1475242924)}));
    BOOST_CHECK(!JWTXX::JWT::verify(tokenWithExp, JWTXX::Key(JWTXX::Algorithm::HS256, "secret-key"), {JWTXX::Validate::nbf(1475242922)}));
    BOOST_CHECK(JWTXX::JWT::verify(tokenWithExp, JWTXX::Key(JWTXX::Algorithm::HS256, "secret-key"), {JWTXX::Validate::nbf(1475242924)}));
    BOOST_CHECK(JWTXX::JWT::verify(tokenWithExp, JWTXX::Key(JWTXX::Algorithm::HS256, "secret-key"), {JWTXX::Validate::exp(1475246522), JWTXX::Validate::iat(1475246522), JWTXX::Validate::nbf(1475246522)}));
    BOOST_CHECK(!JWTXX::JWT::verify(tokenWithExp, JWTXX::Key(JWTXX::Algorithm::HS256, "secret-key"), {JWTXX::Validate::exp(1475246524), JWTXX::Validate::iat(1475246524), JWTXX::Validate::nbf(1475246524)}));
    BOOST_CHECK(!JWTXX::JWT::verify(tokenWithExp, JWTXX::Key(JWTXX::Algorithm::HS256, "secret-key"), {JWTXX::Validate::exp(1475242922), JWTXX::Validate::iat(1475242922), JWTXX::Validate::nbf(1475242922)}));
    BOOST_CHECK(JWTXX::JWT::verify(tokenWithExp, JWTXX::Key(JWTXX::Algorithm::HS256, "secret-key"), {JWTXX::Validate::iss("madf")}));
    BOOST_CHECK(!JWTXX::JWT::verify(tokenWithExp, JWTXX::Key(JWTXX::Algorithm::HS256, "secret-key"), {JWTXX::Validate::iss("somebody")}));
    BOOST_CHECK(JWTXX::JWT::verify(tokenWithExp, JWTXX::Key(JWTXX::Algorithm::HS256, "secret-key"), {JWTXX::Validate::sub("user")}));
    BOOST_CHECK(!JWTXX::JWT::verify(tokenWithExp, JWTXX::Key(JWTXX::Algorithm::HS256, "secret-key"), {JWTXX::Validate::sub("someone")}));
    BOOST_CHECK(JWTXX::JWT::verify(tokenWithExp, JWTXX::Key(JWTXX::Algorithm::HS256, "secret-key"), {JWTXX::Validate::aud("")}));
    BOOST_CHECK(JWTXX::JWT::verify(tokenWithExp, JWTXX::Key(JWTXX::Algorithm::HS256, "secret-key"), {JWTXX::Validate::aud("something")})); // Audience is missing in the token
}

BOOST_AUTO_TEST_CASE(TestParserNoVerify)
{
    auto jwt = JWTXX::JWT::parse(tokenWithExp);
    BOOST_CHECK_EQUAL(jwt.alg(), JWTXX::Algorithm::HS256);
    BOOST_CHECK_EQUAL(jwt.claim("iss").getString(), "madf");
    BOOST_CHECK_EQUAL(jwt.claim("sub").getString(), "user");
    BOOST_CHECK_EQUAL(jwt.claim("exp").getInteger(), 1475246523);
    BOOST_CHECK_EQUAL(jwt.claim("iat").getInteger(), 1475242923);
    BOOST_CHECK_EQUAL(jwt.claim("nbf").getInteger(), 1475242923);
}

BOOST_AUTO_TEST_CASE(TestParserNoVerifyCorruptedSignature)
{
    auto jwt = JWTXX::JWT::parse(tokenCorruptedSign);
    BOOST_CHECK_EQUAL(jwt.alg(), JWTXX::Algorithm::HS256);
    BOOST_CHECK_EQUAL(jwt.claim("iss").getString(), "madf");
    BOOST_CHECK_EQUAL(jwt.claim("sub").getString(), "user");
    BOOST_CHECK_EQUAL(jwt.claim("exp").getInteger(), 1475246523);
    BOOST_CHECK_EQUAL(jwt.claim("iat").getInteger(), 1475242923);
    BOOST_CHECK_EQUAL(jwt.claim("nbf").getInteger(), 1475242923);
}

BOOST_AUTO_TEST_CASE(TestParserExtraVerification)
{
    JWTXX::JWT jwt(tokenWithExp, JWTXX::Key(JWTXX::Algorithm::HS256, "secret-key"), {JWTXX::Validate::exp(1475246522), JWTXX::Validate::iat(1475246522), JWTXX::Validate::nbf(1475246522)});
    BOOST_CHECK_EQUAL(jwt.alg(), JWTXX::Algorithm::HS256);
    BOOST_CHECK_EQUAL(jwt.claim("iss").getString(), "madf");
    BOOST_CHECK_EQUAL(jwt.claim("sub").getString(), "user");
    BOOST_CHECK_EQUAL(jwt.claim("exp").getInteger(), 1475246523);
    BOOST_CHECK_EQUAL(jwt.claim("iat").getInteger(), 1475242923);
    BOOST_CHECK_EQUAL(jwt.claim("nbf").getInteger(), 1475242923);
    BOOST_CHECK_THROW(JWTXX::JWT(tokenCorruptedSign, JWTXX::Key(JWTXX::Algorithm::HS256, "secret-key")), JWTXX::JWT::ValidationError);
    BOOST_CHECK_THROW(JWTXX::JWT(tokenWithExp, JWTXX::Key(JWTXX::Algorithm::HS256, "secret-key"), {JWTXX::Validate::exp(1475242922), JWTXX::Validate::iat(1475242922), JWTXX::Validate::nbf(1475242922)}), JWTXX::JWT::ValidationError);
    BOOST_CHECK_THROW(JWTXX::JWT(tokenWithExp, JWTXX::Key(JWTXX::Algorithm::HS256, "secret-key"), {JWTXX::Validate::exp(1475246524), JWTXX::Validate::iat(1475246524), JWTXX::Validate::nbf(1475246524)}), JWTXX::JWT::ValidationError);
}

BOOST_AUTO_TEST_CASE(TestParserErrors)
{
    BOOST_CHECK_THROW(JWTXX::JWT(brokenTokenWithExp1, JWTXX::Key(JWTXX::Algorithm::HS256, "secret-key"), {JWTXX::Validate::exp(1475242922), JWTXX::Validate::iat(1475242922), JWTXX::Validate::nbf(1475242922)}), JWTXX::JWT::ParseError);
    BOOST_CHECK_THROW(JWTXX::JWT(brokenTokenWithExp2, JWTXX::Key(JWTXX::Algorithm::HS256, "secret-key"), {JWTXX::Validate::exp(1475246524), JWTXX::Validate::iat(1475246524), JWTXX::Validate::nbf(1475246524)}), JWTXX::JWT::ParseError);
    BOOST_CHECK_THROW(JWTXX::JWT(notAToken1, JWTXX::Key(JWTXX::Algorithm::HS256, "secret-key"), {JWTXX::Validate::exp(1475242922), JWTXX::Validate::iat(1475242922), JWTXX::Validate::nbf(1475242922)}), JWTXX::JWT::ParseError);
    BOOST_CHECK_THROW(JWTXX::JWT(notAToken2, JWTXX::Key(JWTXX::Algorithm::HS256, "secret-key"), {JWTXX::Validate::exp(1475246524), JWTXX::Validate::iat(1475246524), JWTXX::Validate::nbf(1475246524)}), JWTXX::JWT::ParseError);
}

BOOST_AUTO_TEST_CASE(TestParserHeaderErrors)
{
    BOOST_CHECK(!JWTXX::JWT::verify(invalidHeaderToken, JWTXX::Key(JWTXX::Algorithm::HS256, "secret-key")));
    BOOST_CHECK_THROW(JWTXX::JWT(invalidHeaderToken, JWTXX::Key(JWTXX::Algorithm::HS256, "secret-key")), JWTXX::JWT::Error);
}
