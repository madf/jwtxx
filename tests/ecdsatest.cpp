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
    BOOST_CHECK(!jwt.token("ecdsa-256-key-pair.pem").empty());
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
    BOOST_CHECK(!jwt.token("ecdsa-256-key-pair.pem").empty());
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
    BOOST_CHECK(!jwt.token("ecdsa-256-key-pair.pem").empty());
}

BOOST_AUTO_TEST_CASE(TestParser256Sig1)
{
    //JWTXX::JWT jwt("eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJtYWRmIn0.MEUCIERctp+BXGdF/NN+5ABMSdZJVXFwXnXrSbKqIKZYOB10AiEAuA+WLlW6ttNJ9p/bcdrr3wGsTAhbHL1uWvGqAmZsGSUA", JWTXX::Key(JWTXX::Algorithm::ES256, "public-ecdsa-256-key.pem"));
    JWTXX::JWT jwt("eyJhbGciOiJFUzI1NiJ9.eyJzdWIiOiJtYW1vbnRvdiIsImlzcyI6IkltYWdpbmUiLCJleHAiOjE0NzM4NjU4MDJ9.31IlTQ_GHH6U-p0bW3NTzWYabbKR9_-2ngGU8fd-5ZKDV3Z6ekVDOX-vfnInJxWQ8y-OQn9ckIcvLhvSBo577A", JWTXX::Key(JWTXX::Algorithm::ES256, "public-ecdsa-256-key.pem"));

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
    JWTXX::JWT jwt("eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJtYWRmIn0.MEUCIAt6P9KZvF7xDJgWteEPFKOrzeBV6yrpCpcU21n39gTFAiEAxzKrbC0w7Vzt3eUCY5fIU1oOlXGpGU9JwE3Uqr2vxlMA", JWTXX::Key(JWTXX::Algorithm::ES256, "public-ecdsa-256-key.pem"));

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
