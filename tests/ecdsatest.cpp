#include "jwtxx/jwt.h"
#include "jwtxx/ios.h"

#include "initopenssl.h"

#define BOOST_TEST_MODULE JWTECDSAAlgTest

#include <boost/test/unit_test.hpp>

namespace
{

constexpr auto token256PartOrder1 = "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJtYWRmIn0";
constexpr auto token256PartOrder2 = "eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJtYWRmIn0";
constexpr auto token256Order1 = "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJtYWRmIn0.MEYCIQDLfrUl5UjzAJRoTSIHWYtrZgGeTVLe7Jbwr8VSdWPX1QIhAO44atlfe9nNKgoG5GjQSjBRFSRZnmfajNma_NVUJTQ4";
constexpr auto token256Order2 = "eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJtYWRmIn0.MEUCIQDxYb1VcYO_q5Cz5BiPiAYq64yXWQnpetbeceeQG1_4YgIgdGXWZPqE5czzYTjxRkQFrJr1SCwmhhZFIn8I1GYgoZI";
constexpr auto token384PartOrder1 = "eyJhbGciOiJFUzM4NCIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJtYWRmIn0";
constexpr auto token384PartOrder2 = "eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzM4NCJ9.eyJpc3MiOiJtYWRmIn0";
constexpr auto token384Order1 = "eyJhbGciOiJFUzM4NCIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJtYWRmIn0.MEQCIEJhk_-PkmS5FyMMn-bH8gNoaFn0x7Pap-KcXEWuhq9wAiAl2mNe4GncJIjjhVyYOxKT42tvoXqHH-iMBFk0JRY98A";
constexpr auto token384Order2 = "eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzM4NCJ9.eyJpc3MiOiJtYWRmIn0.MEUCIQDa3Hp1OG-oiXX2eaznBRup1Y5WqCUTmFEvxTEI-ngE-AIgH_7yc09xb-4EPScqtyIxJuJV0t2Wc93rSKaqswV0whs";
constexpr auto token512PartOrder1 = "eyJhbGciOiJFUzUxMiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJtYWRmIn0";
constexpr auto token512PartOrder2 = "eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzUxMiJ9.eyJpc3MiOiJtYWRmIn0";
constexpr auto token512Order1 = "eyJhbGciOiJFUzUxMiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJtYWRmIn0.MEUCIQCVS5EcXIIYk8BJVTphGS_gIkMDkHS-K5rlTVoi3fTnKAIgfSMsTcnjXQjoi_43hdRWQhiNKKu7D090RjJbYC1w-eg";
constexpr auto token512Order2 = "eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzUxMiJ9.eyJpc3MiOiJtYWRmIn0.MEYCIQCSn5y1q5hQm4kOfP-39rWVNY_61iukR9GUjhn2Y8DuyQIhAMLF77oGoNtNO_buqxZIAwMTPs_TO3FrjbRVua34W-jk";
constexpr auto token512CorruptedSignature = "eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzUxMiJ9.eyJpc3MiOiJtYWRmIn0.MEYCIQCSn5y1q5hQm4kOfP-39rWVNY_61iukR9GUjhn2Y8DuyQIhAMLF77oGoNtNO_buqxZIAwMTPs_TO3FrjbRVua";
constexpr auto brokenToken1 = "eXAiOiJKV1QiLCJhbGciOiJFUzUxMiJ9.eyJpc3MiOiJtYWRmIn0.MEYCIQCSn5y1q5hQm4kOfP-39rWVNY_61iukR9GUjhn2Y8DuyQIhAMLF77oGoNtNO_buqxZIAwMTPs_TO3FrjbRVua34W-jk";
constexpr auto brokenToken2 = "eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzUxMiJ9.3MiOiJtYWRmIn0.MEYCIQCSn5y1q5hQm4kOfP-39rWVNY_61iukR9GUjhn2Y8DuyQIhAMLF77oGoNtNO_buqxZIAwMTPs_TO3FrjbRVua34W-jk";
constexpr auto notAToken1 = "";
constexpr auto notAToken2 = "Hello, World!";
constexpr auto invalidHeaderToken = "eyJhbGciOiJIUzI1NyIsInR5cCI6IkpXIn0.eyJuYW1lIjoiZm9vIn0"; // Here should be a ECDSA signature, but the structure is checked first, so we can skip.

}

BOOST_GLOBAL_FIXTURE(InitOpenSSL);

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
    BOOST_CHECK(part == token256PartOrder1 || part == token256PartOrder2);
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
    BOOST_CHECK(part == token384PartOrder1 || part == token384PartOrder2);
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
    BOOST_CHECK(part == token512PartOrder1 || part == token512PartOrder2);
}

BOOST_AUTO_TEST_CASE(TestParser256Sig1)
{
    JWTXX::JWT jwt(token256Order1, JWTXX::Key(JWTXX::Algorithm::ES256, "public-ecdsa-256-key.pem"));

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
    BOOST_CHECK(part == token256PartOrder1 || part == token256PartOrder2);
}

BOOST_AUTO_TEST_CASE(TestParser256Sig2)
{
    JWTXX::JWT jwt(token256Order2, JWTXX::Key(JWTXX::Algorithm::ES256, "public-ecdsa-256-key.pem"));

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
    BOOST_CHECK(part == token256PartOrder1 || part == token256PartOrder2);
}

BOOST_AUTO_TEST_CASE(TestParser384Sig1)
{
    JWTXX::JWT jwt(token384Order1, JWTXX::Key(JWTXX::Algorithm::ES384, "public-ecdsa-256-key.pem"));

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
    BOOST_CHECK(part == token384PartOrder1 || part == token384PartOrder2);
}

BOOST_AUTO_TEST_CASE(TestParser384Sig2)
{
    JWTXX::JWT jwt(token384Order2, JWTXX::Key(JWTXX::Algorithm::ES384, "public-ecdsa-256-key.pem"));

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
    BOOST_CHECK(part == token384PartOrder1 || part == token384PartOrder2);
}

BOOST_AUTO_TEST_CASE(TestParser512Sig1)
{
    JWTXX::JWT jwt(token512Order1, JWTXX::Key(JWTXX::Algorithm::ES512, "public-ecdsa-256-key.pem"));

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
    BOOST_CHECK(part == token512PartOrder1 || part == token512PartOrder2);
}

BOOST_AUTO_TEST_CASE(TestParser512Sig2)
{
    JWTXX::JWT jwt(token512Order2, JWTXX::Key(JWTXX::Algorithm::ES512, "public-ecdsa-256-key.pem"));

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
    BOOST_CHECK(part == token512PartOrder1 || part == token512PartOrder2);
}

BOOST_AUTO_TEST_CASE(TestParserWithCert256Sig1)
{
    JWTXX::JWT jwt(token256Order1, JWTXX::Key(JWTXX::Algorithm::ES256, "ecdsa-cert.pem"));

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
    BOOST_CHECK(part == token256PartOrder1 || part == token256PartOrder2);
}

BOOST_AUTO_TEST_CASE(TestParserWithCert256Sig2)
{
    JWTXX::JWT jwt(token256Order2, JWTXX::Key(JWTXX::Algorithm::ES256, "ecdsa-cert.pem"));

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
    BOOST_CHECK(part == token256PartOrder1 || part == token256PartOrder2);
}

BOOST_AUTO_TEST_CASE(TestParserWithCert384Sig1)
{
    JWTXX::JWT jwt(token384Order1, JWTXX::Key(JWTXX::Algorithm::ES384, "ecdsa-cert.pem"));

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
    BOOST_CHECK(part == token384PartOrder1 || part == token384PartOrder2);
}

BOOST_AUTO_TEST_CASE(TestParserWithCert384Sig2)
{
    JWTXX::JWT jwt(token384Order2, JWTXX::Key(JWTXX::Algorithm::ES384, "ecdsa-cert.pem"));

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
    BOOST_CHECK(part == token384PartOrder1 || part == token384PartOrder2);
}

BOOST_AUTO_TEST_CASE(TestParserWithCert512Sig1)
{
    JWTXX::JWT jwt(token512Order1, JWTXX::Key(JWTXX::Algorithm::ES512, "ecdsa-cert.pem"));

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
    BOOST_CHECK(part == token512PartOrder1 || part == token512PartOrder2);
}

BOOST_AUTO_TEST_CASE(TestParserWithCert512Sig2)
{
    JWTXX::JWT jwt(token512Order2, JWTXX::Key(JWTXX::Algorithm::ES512, "ecdsa-cert.pem"));

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
    BOOST_CHECK(part == token512PartOrder1 || part == token512PartOrder2);
}

BOOST_AUTO_TEST_CASE(TestParserNoVerify)
{
    auto jwt1 = JWTXX::JWT::parse(token512Order1);
    BOOST_CHECK_EQUAL(jwt1.alg(), JWTXX::Algorithm::ES512);
    auto jwt2 = JWTXX::JWT::parse(token512Order1);
    BOOST_CHECK_EQUAL(jwt2.alg(), JWTXX::Algorithm::ES512);
}

BOOST_AUTO_TEST_CASE(TestParserNoVerifyCorruptedSignature)
{
    auto jwt = JWTXX::JWT::parse(token512CorruptedSignature);
    BOOST_CHECK_EQUAL(jwt.alg(), JWTXX::Algorithm::ES512);
}

BOOST_AUTO_TEST_CASE(TestParserExtraVerification)
{
    // TODO: add tests for claim verification
    BOOST_CHECK_THROW(JWTXX::JWT(token512CorruptedSignature, JWTXX::Key(JWTXX::Algorithm::ES512, "ecdsa-cert.pem")), JWTXX::JWT::ValidationError);
}

BOOST_AUTO_TEST_CASE(TestParserErrors)
{
    BOOST_CHECK_THROW(JWTXX::JWT(brokenToken1, JWTXX::Key(JWTXX::Algorithm::ES512, "ecdsa-cert.pem")), JWTXX::JWT::ParseError);
    BOOST_CHECK_THROW(JWTXX::JWT(brokenToken2, JWTXX::Key(JWTXX::Algorithm::ES512, "ecdsa-cert.pem")), JWTXX::JWT::ParseError);
    BOOST_CHECK_THROW(JWTXX::JWT(notAToken1, JWTXX::Key(JWTXX::Algorithm::ES512, "ecdsa-cert.pem")), JWTXX::JWT::ParseError);
    BOOST_CHECK_THROW(JWTXX::JWT(notAToken2, JWTXX::Key(JWTXX::Algorithm::ES512, "ecdsa-cert.pem")), JWTXX::JWT::ParseError);
}

BOOST_AUTO_TEST_CASE(TestParserHeaderErrors)
{
    BOOST_CHECK(!JWTXX::JWT::verify(invalidHeaderToken, JWTXX::Key(JWTXX::Algorithm::ES256, "public-ecdsa-256-key.pem")));
    BOOST_CHECK_THROW(JWTXX::JWT(invalidHeaderToken, JWTXX::Key(JWTXX::Algorithm::ES256, "public-ecdsa-256-key.pem")), JWTXX::JWT::ValidationError);
}

BOOST_AUTO_TEST_CASE(TestCtor256PwNoCallback)
{
    JWTXX::JWT jwt(JWTXX::Algorithm::ES256, {{"iss", "madf"}});

    BOOST_CHECK_EQUAL(jwt.alg(), JWTXX::Algorithm::ES256);
    BOOST_CHECK(!jwt.claims().empty());
    BOOST_CHECK(!jwt.header().empty());
    auto header = jwt.header();
    BOOST_CHECK_EQUAL(header["alg"], "ES256");
    BOOST_CHECK_EQUAL(header["typ"], "JWT");
    BOOST_CHECK_EQUAL(jwt.claim("iss"), "madf");
    BOOST_CHECK_THROW(jwt.token("ecdsa-256-key-pair-pw.pem"), JWTXX::Key::Error);
    BOOST_CHECK_THROW(jwt.token("ecdsa-256-key-pair-pw.pem", [](){ return "abc"; }), JWTXX::Key::Error);
}

BOOST_AUTO_TEST_CASE(TestCtor256Pw)
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
    auto token = jwt.token("ecdsa-256-key-pair-pw.pem", [](){ return "123456"; });
    auto part = token.substr(0, 56);
    BOOST_CHECK(part == token256PartOrder1 || part == token256PartOrder2);
}

BOOST_AUTO_TEST_CASE(TestCtor384Pw)
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
    auto token = jwt.token("ecdsa-256-key-pair-pw.pem", [](){ return "123456"; });
    auto part = token.substr(0, 56);
    BOOST_CHECK(part == token384PartOrder1 || part == token384PartOrder2);
}

BOOST_AUTO_TEST_CASE(TestCtor512Pw)
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
    auto token = jwt.token("ecdsa-256-key-pair-pw.pem", [](){ return "123456"; });
    auto part = token.substr(0, 56);
    BOOST_CHECK(part == token512PartOrder1 || part == token512PartOrder2);
}
