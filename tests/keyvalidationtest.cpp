#include "jwtxx/jwt.h"

#include "initopenssl.h"

#define BOOST_TEST_MODULE JWTKeyValidationTest

#include <boost/test/unit_test.hpp>

using JWTXX::Value;

namespace
{

constexpr auto rsaKeyFile = "rsa-2048-key-pair.pem";
constexpr auto ecKeyFile = "ecdsa-256-key-pair.pem";
constexpr auto rsaPubKeyFile = "public-rsa-2048-key.pem";
constexpr auto ecPubKeyFile = "public-ecdsa-256-key.pem";

}

BOOST_GLOBAL_FIXTURE(InitOpenSSL);

BOOST_AUTO_TEST_CASE(TestECPubKeyWithRSAAlgorithm)
{
    JWTXX::JWT jwt(JWTXX::Algorithm::RS256, {{"sub", Value("test")}});
    auto token = jwt.token(rsaKeyFile);

    BOOST_CHECK_THROW(JWTXX::JWT(token, JWTXX::Key(JWTXX::Algorithm::RS256, ecPubKeyFile)), JWTXX::Key::Error);
}

BOOST_AUTO_TEST_CASE(TestRSAPubKeyWithECAlgorithm)
{
    JWTXX::JWT jwt(JWTXX::Algorithm::ES256, {{"sub", Value("test")}});
    auto token = jwt.token(ecKeyFile);

    BOOST_CHECK_THROW(JWTXX::JWT(token, JWTXX::Key(JWTXX::Algorithm::ES256, rsaPubKeyFile)), JWTXX::Key::Error);
}

BOOST_AUTO_TEST_CASE(TestAlgorithmMismatchRS256WithHS256)
{
    JWTXX::JWT jwt(JWTXX::Algorithm::RS256, {{"sub", Value("test")}});
    JWTXX::Key key(JWTXX::Algorithm::HS256, "secret");

    BOOST_CHECK_THROW(jwt.token(key), JWTXX::JWT::Error);
}

BOOST_AUTO_TEST_CASE(TestAlgorithmMismatchHS256WithRS256)
{
    JWTXX::JWT jwt(JWTXX::Algorithm::HS256, {{"sub", Value("test")}});
    JWTXX::Key key(JWTXX::Algorithm::RS256, rsaKeyFile);

    BOOST_CHECK_THROW(jwt.token(key), JWTXX::JWT::Error);
}

BOOST_AUTO_TEST_CASE(TestAlgorithmMismatchES256WithRS256)
{
    JWTXX::JWT jwt(JWTXX::Algorithm::ES256, {{"sub", Value("test")}});
    JWTXX::Key key(JWTXX::Algorithm::RS256, rsaKeyFile);

    BOOST_CHECK_THROW(jwt.token(key), JWTXX::JWT::Error);
}

BOOST_AUTO_TEST_CASE(TestAlgorithmMismatchRS256WithES256)
{
    JWTXX::JWT jwt(JWTXX::Algorithm::RS256, {{"sub", Value("test")}});
    JWTXX::Key key(JWTXX::Algorithm::ES256, ecKeyFile);

    BOOST_CHECK_THROW(jwt.token(key), JWTXX::JWT::Error);
}

BOOST_AUTO_TEST_CASE(TestAlgorithmMismatchHS256WithHS512)
{
    JWTXX::JWT jwt(JWTXX::Algorithm::HS256, {{"sub", Value("test")}});
    JWTXX::Key key(JWTXX::Algorithm::HS512, "secret");

    BOOST_CHECK_THROW(jwt.token(key), JWTXX::JWT::Error);
}

BOOST_AUTO_TEST_CASE(TestAlgorithmMismatchRS256WithRS512)
{
    JWTXX::JWT jwt(JWTXX::Algorithm::RS256, {{"sub", Value("test")}});
    JWTXX::Key key(JWTXX::Algorithm::RS512, rsaKeyFile);

    BOOST_CHECK_THROW(jwt.token(key), JWTXX::JWT::Error);
}

BOOST_AUTO_TEST_CASE(TestAlgorithmMismatchES256WithES384)
{
    JWTXX::JWT jwt(JWTXX::Algorithm::ES256, {{"sub", Value("test")}});
    JWTXX::Key key(JWTXX::Algorithm::ES384, ecKeyFile);

    BOOST_CHECK_THROW(jwt.token(key), JWTXX::JWT::Error);
}
