#include "jwtxx/jwt.h"
#include "jwtxx/ios.h"

#include "initopenssl.h"

#define BOOST_TEST_MODULE JWTNoneAlgTest

#include <boost/test/unit_test.hpp>

using JWTXX::Value;

namespace
{

constexpr auto tokenOrder1 = "eyJ0eXAiOiJKV1QiLCJhbGciOiJub25lIn0.eyJpc3MiOiJtYWRmIn0";
constexpr auto tokenOrder2 = "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJpc3MiOiJtYWRmIn0";
constexpr auto tokenWithExp = "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJpc3MiOiJtYWRmIiwic3ViIjoidXNlciIsIm5iZiI6MTQ3NTI0MDY0NiwiZXhwIjoxNDc1MjQ0MjQ2LCJpYXQiOjE0NzUyNDA2NDZ9";
constexpr auto brokenTokenWithExp1 = "bGciOiJub25lIiwidHlwIjoiSldUIn0.eyJpc3MiOiJtYWRmIiwic3ViIjoidXNlciIsIm5iZiI6MTQ3NTI0MDY0NiwiZXhwIjoxNDc1MjQ0MjQ2LCJpYXQiOjE0NzUyNDA2NDZ9";
constexpr auto brokenTokenWithExp2 = "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.c3MiOiJtYWRmIiwic3ViIjoidXNlciIsIm5iZiI6MTQ3NTI0MDY0NiwiZXhwIjoxNDc1MjQ0MjQ2LCJpYXQiOjE0NzUyNDA2NDZ9";
constexpr auto notAToken1 = "";
constexpr auto notAToken2 = "Hello, World!";
constexpr auto invalidHeaderToken = "eyJhbGciOiJIUzI1NyIsInR5cCI6IkpXIn0.eyJuYW1lIjoiZm9vIn0";
constexpr auto noTypToken = "eyJhbGciOiJub25lIn0.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9";
constexpr auto wrongCaseTypToken = "eyJhbGciOiJub25lIiwidHlwIjoiald0In0.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9";
constexpr auto nonJWTTypToken = "eyJhbGciOiJub25lIiwidHlwIjoiald0eHgifQ.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9";

}

BOOST_GLOBAL_FIXTURE(InitOpenSSL);

BOOST_AUTO_TEST_CASE(TestCtor)
{
    JWTXX::JWT jwt(JWTXX::Algorithm::none, {{"iss", Value("madf")}});

    BOOST_CHECK_EQUAL(jwt.alg(), JWTXX::Algorithm::none);
    BOOST_CHECK(!jwt.claims().empty());
    BOOST_CHECK(!jwt.header().empty());
    auto header = jwt.header();
    BOOST_CHECK_EQUAL(header["alg"].getString(), "none");
    BOOST_CHECK_EQUAL(header["typ"].getString(), "JWT");
    BOOST_CHECK_EQUAL(jwt.claim("iss").getString(), "madf");
    auto token = jwt.token("");
    // Jansson uses hashtables form JSON objects and hash function implementation reads over the boundary of the string, yet word-aligned, so actual order of header fields and claims is undefined.
    BOOST_CHECK(token == tokenOrder1 || token == tokenOrder2);
}

BOOST_AUTO_TEST_CASE(TestParser)
{
    JWTXX::JWT jwt(tokenOrder1, JWTXX::Key(JWTXX::Algorithm::none, ""));

    BOOST_CHECK_EQUAL(jwt.alg(), JWTXX::Algorithm::none);
    BOOST_CHECK(!jwt.claims().empty());
    BOOST_CHECK(!jwt.header().empty());
    auto header = jwt.header();
    BOOST_CHECK_EQUAL(header["alg"].getString(), "none");
    BOOST_CHECK_EQUAL(header["typ"].getString(), "JWT");
    BOOST_CHECK_EQUAL(jwt.claim("iss").getString(), "madf");
    auto token = jwt.token("");
    // Jansson uses hashtables form JSON objects and hash function implementation reads over the boundary of the string, yet word-aligned, so actual order of header fields and claims is undefined.
    BOOST_CHECK(token == tokenOrder1 || token == tokenOrder2);
}

BOOST_AUTO_TEST_CASE(TestParserDifferentFieldOrder)
{
    JWTXX::JWT jwt(tokenOrder2, JWTXX::Key(JWTXX::Algorithm::none, ""));

    BOOST_CHECK_EQUAL(jwt.alg(), JWTXX::Algorithm::none);
    BOOST_CHECK(!jwt.claims().empty());
    BOOST_CHECK(!jwt.header().empty());
    auto header = jwt.header();
    BOOST_CHECK_EQUAL(header["alg"].getString(), "none");
    BOOST_CHECK_EQUAL(header["typ"].getString(), "JWT");
    BOOST_CHECK_EQUAL(jwt.claim("iss").getString(), "madf");
    auto token = jwt.token("");
    // Jansson uses hashtables form JSON objects and hash function implementation reads over the boundary of the string, yet word-aligned, so actual order of header fields and claims is undefined.
    BOOST_CHECK(token == tokenOrder1 || token == tokenOrder2);
}

BOOST_AUTO_TEST_CASE(TestVerifier)
{
    BOOST_CHECK(JWTXX::JWT::verify(tokenOrder1, JWTXX::Key(JWTXX::Algorithm::none, "")));
    BOOST_CHECK(JWTXX::JWT::verify(tokenWithExp, JWTXX::Key(JWTXX::Algorithm::none, ""), {JWTXX::Validate::exp(1475244245)}));
    BOOST_CHECK(!JWTXX::JWT::verify(tokenWithExp, JWTXX::Key(JWTXX::Algorithm::none, ""), {JWTXX::Validate::exp(1475244247)}));
    BOOST_CHECK(!JWTXX::JWT::verify(tokenWithExp, JWTXX::Key(JWTXX::Algorithm::none, ""), {JWTXX::Validate::iat(1475240645)}));
    BOOST_CHECK(JWTXX::JWT::verify(tokenWithExp, JWTXX::Key(JWTXX::Algorithm::none, ""), {JWTXX::Validate::iat(1475240647)}));
    BOOST_CHECK(!JWTXX::JWT::verify(tokenWithExp, JWTXX::Key(JWTXX::Algorithm::none, ""), {JWTXX::Validate::nbf(1475240645)}));
    BOOST_CHECK(JWTXX::JWT::verify(tokenWithExp, JWTXX::Key(JWTXX::Algorithm::none, ""), {JWTXX::Validate::nbf(1475240647)}));
    BOOST_CHECK(JWTXX::JWT::verify(tokenWithExp, JWTXX::Key(JWTXX::Algorithm::none, ""), {JWTXX::Validate::exp(1475244245), JWTXX::Validate::iat(1475244245), JWTXX::Validate::nbf(1475244245)}));
    BOOST_CHECK(!JWTXX::JWT::verify(tokenWithExp, JWTXX::Key(JWTXX::Algorithm::none, ""), {JWTXX::Validate::exp(1475244247), JWTXX::Validate::iat(1475244247), JWTXX::Validate::nbf(1475244247)}));
    BOOST_CHECK(!JWTXX::JWT::verify(tokenWithExp, JWTXX::Key(JWTXX::Algorithm::none, ""), {JWTXX::Validate::exp(1475240645), JWTXX::Validate::iat(1475240645), JWTXX::Validate::nbf(1475240645)}));
    BOOST_CHECK(JWTXX::JWT::verify(tokenWithExp, JWTXX::Key(JWTXX::Algorithm::none, ""), {JWTXX::Validate::iss("madf")}));
    BOOST_CHECK(!JWTXX::JWT::verify(tokenWithExp, JWTXX::Key(JWTXX::Algorithm::none, ""), {JWTXX::Validate::iss("somebody")}));
    BOOST_CHECK(JWTXX::JWT::verify(tokenWithExp, JWTXX::Key(JWTXX::Algorithm::none, ""), {JWTXX::Validate::sub("user")}));
    BOOST_CHECK(!JWTXX::JWT::verify(tokenWithExp, JWTXX::Key(JWTXX::Algorithm::none, ""), {JWTXX::Validate::sub("someone")}));
    BOOST_CHECK(JWTXX::JWT::verify(tokenWithExp, JWTXX::Key(JWTXX::Algorithm::none, ""), {JWTXX::Validate::aud("")}));
    BOOST_CHECK(JWTXX::JWT::verify(tokenWithExp, JWTXX::Key(JWTXX::Algorithm::none, ""), {JWTXX::Validate::aud("something")})); // Audience is missing in the token
}

BOOST_AUTO_TEST_CASE(TestParserNoVerify)
{
    auto jwt = JWTXX::JWT::parse(tokenWithExp);
    BOOST_CHECK_EQUAL(jwt.alg(), JWTXX::Algorithm::none);
    BOOST_CHECK_EQUAL(jwt.claim("iss").getString(), "madf");
    BOOST_CHECK_EQUAL(jwt.claim("sub").getString(), "user");
    BOOST_CHECK_EQUAL(jwt.claim("exp").getInteger(), 1475244246);
    BOOST_CHECK_EQUAL(jwt.claim("iat").getInteger(), 1475240646);
    BOOST_CHECK_EQUAL(jwt.claim("nbf").getInteger(), 1475240646);
}

BOOST_AUTO_TEST_CASE(TestParserExtraVerification)
{
    JWTXX::JWT jwt(tokenWithExp, JWTXX::Key(JWTXX::Algorithm::none, ""), {JWTXX::Validate::exp(1475244245), JWTXX::Validate::iat(1475244245), JWTXX::Validate::nbf(1475244245)});
    BOOST_CHECK_EQUAL(jwt.alg(), JWTXX::Algorithm::none);
    BOOST_CHECK_EQUAL(jwt.claim("iss").getString(), "madf");
    BOOST_CHECK_EQUAL(jwt.claim("sub").getString(), "user");
    BOOST_CHECK_EQUAL(jwt.claim("exp").getInteger(), 1475244246);
    BOOST_CHECK_EQUAL(jwt.claim("iat").getInteger(), 1475240646);
    BOOST_CHECK_EQUAL(jwt.claim("nbf").getInteger(), 1475240646);
    BOOST_CHECK_THROW(JWTXX::JWT(tokenWithExp, JWTXX::Key(JWTXX::Algorithm::none, ""), {JWTXX::Validate::exp(1475244247), JWTXX::Validate::iat(1475244247), JWTXX::Validate::nbf(1475244247)}), JWTXX::JWT::ValidationError);
    BOOST_CHECK_THROW(JWTXX::JWT(tokenWithExp, JWTXX::Key(JWTXX::Algorithm::none, ""), {JWTXX::Validate::exp(1475240645), JWTXX::Validate::iat(1475240645), JWTXX::Validate::nbf(1475240645)}), JWTXX::JWT::ValidationError);
}

BOOST_AUTO_TEST_CASE(TestParserErrors)
{
    BOOST_CHECK_THROW(JWTXX::JWT(brokenTokenWithExp1, JWTXX::Key(JWTXX::Algorithm::none, ""), {JWTXX::Validate::exp(1475244247), JWTXX::Validate::iat(1475244247), JWTXX::Validate::nbf(1475244247)}), JWTXX::JWT::ParseError);
    BOOST_CHECK_THROW(JWTXX::JWT(brokenTokenWithExp2, JWTXX::Key(JWTXX::Algorithm::none, ""), {JWTXX::Validate::exp(1475244247), JWTXX::Validate::iat(1475244247), JWTXX::Validate::nbf(1475244247)}), JWTXX::JWT::ParseError);
    BOOST_CHECK_THROW(JWTXX::JWT(notAToken1, JWTXX::Key(JWTXX::Algorithm::none, ""), {JWTXX::Validate::exp(1475244247), JWTXX::Validate::iat(1475244247), JWTXX::Validate::nbf(1475244247)}), JWTXX::JWT::ParseError);
    BOOST_CHECK_THROW(JWTXX::JWT(notAToken2, JWTXX::Key(JWTXX::Algorithm::none, ""), {JWTXX::Validate::exp(1475244247), JWTXX::Validate::iat(1475244247), JWTXX::Validate::nbf(1475244247)}), JWTXX::JWT::ParseError);
}

BOOST_AUTO_TEST_CASE(TestParserHeaderErrors)
{
    BOOST_CHECK(!JWTXX::JWT::verify(invalidHeaderToken, JWTXX::Key(JWTXX::Algorithm::none, "")));
    BOOST_CHECK_THROW(JWTXX::JWT(invalidHeaderToken, JWTXX::Key(JWTXX::Algorithm::none, "")), JWTXX::JWT::Error);
}

BOOST_AUTO_TEST_CASE(TestParserNoTyp)
{
    BOOST_CHECK(JWTXX::JWT::verify(noTypToken, JWTXX::Key(JWTXX::Algorithm::none, "")));
    BOOST_CHECK_NO_THROW(JWTXX::JWT(noTypToken, JWTXX::Key(JWTXX::Algorithm::none, "")));
}

BOOST_AUTO_TEST_CASE(TestParserWrongCaseTyp)
{
    BOOST_CHECK(JWTXX::JWT::verify(wrongCaseTypToken, JWTXX::Key(JWTXX::Algorithm::none, "")));
    BOOST_CHECK_NO_THROW(JWTXX::JWT(wrongCaseTypToken, JWTXX::Key(JWTXX::Algorithm::none, "")));
}

BOOST_AUTO_TEST_CASE(TestParserNonJWTTyp)
{
    BOOST_CHECK(JWTXX::JWT::verify(nonJWTTypToken, JWTXX::Key(JWTXX::Algorithm::none, "")));
    BOOST_CHECK_NO_THROW(JWTXX::JWT(nonJWTTypToken, JWTXX::Key(JWTXX::Algorithm::none, "")));
}
