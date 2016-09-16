#include "jwtxx/jwt.h"
#include "jwtxx/ios.h"

#include "initopenssl.h"

#define BOOST_TEST_MODULE JWTECDSAAlgTest

#include <boost/test/included/unit_test.hpp>

BOOST_GLOBAL_FIXTURE(InitOpenSSL)

BOOST_AUTO_TEST_CASE(TestCtor256)
{
    JWTXX::JWT jwt(JWTXX::Algorithm::ES256, {{"iss", "madf"}});

    BOOST_CHECK_EQUAL(jwt.alg(), JWTXX::Algorithm::ES256);
    BOOST_CHECK(!jwt.claims().empty());
    BOOST_CHECK(!jwt.header().empty());
    auto header = jwt.header();
    BOOST_CHECK_EQUAL(header["alg"], "ES256");
    BOOST_CHECK_EQUAL(header["typ"], "JWT");
    BOOST_CHECK_EQUAL(jwt.claim("iss"), "madf");
    // ECDSA uses random nonce value, so the signature is always different and it is impossible to check its correctness by simple comparison. Due to the nature of ECDSA, non-random none makes possible recovery of the private key.
    // There is an RFS 6979 which provide ECDSA algorithm with deterministic nonce that solves problem of private key recovery.
    auto token = jwt.token("ecdsa-256-key-pair.pem");
    auto part = token.substr(0, 56);
    BOOST_CHECK(part == "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJtYWRmIn0" || part == "eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJtYWRmIn0");
    std::cout << token << std::endl;
}

BOOST_AUTO_TEST_CASE(TestCtor384)
{
    JWTXX::JWT jwt(JWTXX::Algorithm::ES384, {{"iss", "madf"}});

    BOOST_CHECK_EQUAL(jwt.alg(), JWTXX::Algorithm::ES384);
    BOOST_CHECK(!jwt.claims().empty());
    BOOST_CHECK(!jwt.header().empty());
    auto header = jwt.header();
    BOOST_CHECK_EQUAL(header["alg"], "ES384");
    BOOST_CHECK_EQUAL(header["typ"], "JWT");
    BOOST_CHECK_EQUAL(jwt.claim("iss"), "madf");
    // ECDSA uses random nonce value, so the signature is always different and it is impossible to check its correctness by simple comparison. Due to the nature of ECDSA, non-random none makes possible recovery of the private key.
    // There is an RFS 6979 which provide ECDSA algorithm with deterministic nonce that solves problem of private key recovery.
    auto token = jwt.token("ecdsa-256-key-pair.pem");
    auto part = token.substr(0, 56);
    BOOST_CHECK(part == "eyJhbGciOiJFUzM4NCIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJtYWRmIn0" || part == "eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzM4NCJ9.eyJpc3MiOiJtYWRmIn0");
    std::cout << token << std::endl;
}

BOOST_AUTO_TEST_CASE(TestCtor512)
{
    JWTXX::JWT jwt(JWTXX::Algorithm::ES512, {{"iss", "madf"}});

    BOOST_CHECK_EQUAL(jwt.alg(), JWTXX::Algorithm::ES512);
    BOOST_CHECK(!jwt.claims().empty());
    BOOST_CHECK(!jwt.header().empty());
    auto header = jwt.header();
    BOOST_CHECK_EQUAL(header["alg"], "ES512");
    BOOST_CHECK_EQUAL(header["typ"], "JWT");
    BOOST_CHECK_EQUAL(jwt.claim("iss"), "madf");
    // ECDSA uses random nonce value, so the signature is always different and it is impossible to check its correctness by simple comparison. Due to the nature of ECDSA, non-random none makes possible recovery of the private key.
    // There is an RFS 6979 which provide ECDSA algorithm with deterministic nonce that solves problem of private key recovery.
    auto token = jwt.token("ecdsa-256-key-pair.pem");
    auto part = token.substr(0, 56);
    BOOST_CHECK(part == "eyJhbGciOiJFUzUxMiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJtYWRmIn0" || part == "eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzUxMiJ9.eyJpc3MiOiJtYWRmIn0");
    std::cout << token << std::endl;
}

BOOST_AUTO_TEST_CASE(TestParser256Sig1)
{
    JWTXX::JWT jwt("eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJtYWRmIn0.MEYCIQDLfrUl5UjzAJRoTSIHWYtrZgGeTVLe7Jbwr8VSdWPX1QIhAO44atlfe9nNKgoG5GjQSjBRFSRZnmfajNma_NVUJTQ4", JWTXX::Key(JWTXX::Algorithm::ES256, "public-ecdsa-256-key.pem"));

    BOOST_CHECK_EQUAL(jwt.alg(), JWTXX::Algorithm::ES256);
    BOOST_CHECK(!jwt.claims().empty());
    BOOST_CHECK(!jwt.header().empty());
    auto header = jwt.header();
    BOOST_CHECK_EQUAL(header["alg"], "ES256");
    BOOST_CHECK_EQUAL(header["typ"], "JWT");
    BOOST_CHECK_EQUAL(jwt.claim("iss"), "madf");
    // ECDSA uses random nonce value, so the signature is always different and it is impossible to check its correctness by simple comparison. Due to the nature of ECDSA, non-random none makes possible recovery of the private key.
    // There is an RFS 6979 which provide ECDSA algorithm with deterministic nonce that solves problem of private key recovery.
    BOOST_CHECK(!jwt.token("ecdsa-256-key-pair.pem").empty());
}

BOOST_AUTO_TEST_CASE(TestParser256Sig2)
{
    //JWTXX::JWT jwt("eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJtYWRmIn0.MEYCIQCAoUsDybFjeWYB3k12iNSLupk3I0iqxaQYPcoculvpIgIhAMgo1i0F7aPwCk2G3FquL7SpPpKtml76CASXgZxmC5Kv", JWTXX::Key(JWTXX::Algorithm::ES256, "public-ecdsa-256-key.pem"));
    JWTXX::JWT jwt("eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJtYWRmIn0.MEUCIQCXgl-6ZJB5_xYHxrzvMVudzOcqo_sTMfSuIo3cwUofVgIgC2gWYZ3hig2v9HtzNRfnjE77cgBG3grXmv_qkmYmRc4A", JWTXX::Key(JWTXX::Algorithm::ES256, "public-ecdsa-256-key.pem"));

    BOOST_CHECK_EQUAL(jwt.alg(), JWTXX::Algorithm::ES256);
    BOOST_CHECK(!jwt.claims().empty());
    BOOST_CHECK(!jwt.header().empty());
    auto header = jwt.header();
    BOOST_CHECK_EQUAL(header["alg"], "ES256");
    BOOST_CHECK_EQUAL(header["typ"], "JWT");
    BOOST_CHECK_EQUAL(jwt.claim("iss"), "madf");
    // ECDSA uses random nonce value, so the signature is always different and it is impossible to check its correctness by simple comparison. Due to the nature of ECDSA, non-random none makes possible recovery of the private key.
    // There is an RFS 6979 which provide ECDSA algorithm with deterministic nonce that solves problem of private key recovery.
    BOOST_CHECK(!jwt.token("ecdsa-256-key-pair.pem").empty());
}
