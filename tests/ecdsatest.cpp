#include "jwtxx/jwt.h"
#include "jwtxx/ios.h"

#include "initopenssl.h"

#define BOOST_TEST_MODULE JWTECDSAAlgTest

#include <boost/test/unit_test.hpp>

using JWTXX::Value;

namespace
{

constexpr auto token256PartOrder1 = "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJtYWRmIn0";
constexpr auto token256PartOrder2 = "eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJtYWRmIn0";
constexpr auto token256Order1 = "eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJtYWRmIn0.hMRWgWiRnxffrdV-8bu0nMgZ1GWUVcVb-q9Gph47mfa15ueWwrf4UiFjqqmWEapIo0K4nx6wheFlQz23E9lT7g";
constexpr auto token256Order2 = "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJtYWRmIn0.aZUa7hK6s_rE-wCC9j7_jnG7A6nFD7Jx16hPIGqphht9dTGglLoJi960CtrvRYpQ0cJY_ejKz6TUyEVzS6d3vA";
constexpr auto token384PartOrder1 = "eyJhbGciOiJFUzM4NCIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJtYWRmIn0";
constexpr auto token384PartOrder2 = "eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzM4NCJ9.eyJpc3MiOiJtYWRmIn0";
constexpr auto token384Order1 = "eyJhbGciOiJFUzM4NCIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJtYWRmIn0.qgFjEwBCBRmkQqcXZKOiJ36LaVv7wRhS6RWGXb15x92yOxOg8Yg37WxgbVgH5o6tzMnDaCT2KJ0emhPfi7EIbA";
constexpr auto token384Order2 = "eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzM4NCJ9.eyJpc3MiOiJtYWRmIn0.eHjG5HDw34FcznFIJTQwVlLxg01ob38_WCAquhTV1sdQ6yRF6YCzTVYH0rwt92RHWzVyHTMQoAsbMuP4Hv5iZg";
constexpr auto token512PartOrder1 = "eyJhbGciOiJFUzUxMiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJtYWRmIn0";
constexpr auto token512PartOrder2 = "eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzUxMiJ9.eyJpc3MiOiJtYWRmIn0";
constexpr auto token512Order1 = "eyJhbGciOiJFUzUxMiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJtYWRmIn0.5hKzWLIC7cMHAA5H7RJq7zJ74DoUTRN0fOFo8lgd0Axn-VDS-ekygXmEcRMs5E3SASvXMpc6MYEsdqeBBHqXBw";
constexpr auto token512Order2 = "eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzUxMiJ9.eyJpc3MiOiJtYWRmIn0.7CAxZNbDiWAgloBmcU3p32FcarbkVGXUTz5hXkNm9ETciX8ENYJHqY0o4j6kNj-p9v5vdeGB7DnkdLbYMut52w";
constexpr auto token512CorruptedSignature = "eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzUxMiJ9.eyJpc3MiOiJtYWRmIn0.MEYCIQCSn5y1q5hQm4kOfP-39rWVNY_61iukR9GUjhn2Y8DuyQIhAMLF77oGoNtNO_buqxZIAwMTPs_TO3FrjbRVua";
constexpr auto tokenWithExp = "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE0NzUyNDY1MjMsIm5iZiI6MTQ3NTI0MjkyMywiaWF0IjoxNDc1MjQyOTIzLCJpc3MiOiJtYWRmIiwic3ViIjoidXNlciJ9.7j20ZNmmQEH1etP5uMrvW6Zzoh9c5CYenulCrLrQeSNWh_QbW0Ro-APwY9DMrPksx1pJPiCpBTwG8iVOfOAvdQ";
constexpr auto brokenToken1 = "eXAiOiJKV1QiLCJhbGciOiJFUzUxMiJ9.eyJpc3MiOiJtYWRmIn0.MEYCIQCSn5y1q5hQm4kOfP-39rWVNY_61iukR9GUjhn2Y8DuyQIhAMLF77oGoNtNO_buqxZIAwMTPs_TO3FrjbRVua34W-jk";
constexpr auto brokenToken2 = "eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzUxMiJ9.3MiOiJtYWRmIn0.MEYCIQCSn5y1q5hQm4kOfP-39rWVNY_61iukR9GUjhn2Y8DuyQIhAMLF77oGoNtNO_buqxZIAwMTPs_TO3FrjbRVua34W-jk";
constexpr auto notAToken1 = "";
constexpr auto notAToken2 = "Hello, World!";
constexpr auto invalidHeaderToken = "eyJhbGciOiJIUzI1NyIsInR5cCI6IkpXIn0.eyJuYW1lIjoiZm9vIn0"; // Here should be a ECDSA signature, but the structure is checked first, so we can skip.
constexpr auto publicecdsa256keydata = "-----BEGIN PUBLIC KEY-----\n"
                                       "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEyeJHlnlG6exAXB7XLRqVNI9YHfe4\n"
                                       "LNq1/FsrfFSsknIe/a1j9Z50xnvqkTQcsB+mRzKb8lQynRpXvKHbsoCmTw==\n"
                                       "-----END PUBLIC KEY-----";

}

BOOST_GLOBAL_FIXTURE(InitOpenSSL);

BOOST_AUTO_TEST_CASE(TestCtor256)
{
    JWTXX::JWT jwt(JWTXX::Algorithm::ES256, {{"iss", Value("madf")}});

    BOOST_CHECK_EQUAL(jwt.alg(), JWTXX::Algorithm::ES256);
    BOOST_CHECK(!jwt.claims().empty());
    BOOST_CHECK(!jwt.header().empty());
    auto header = jwt.header();
    BOOST_CHECK_EQUAL(header["alg"].getString(), "ES256");
    BOOST_CHECK_EQUAL(header["typ"].getString(), "JWT");
    BOOST_CHECK_EQUAL(jwt.claim("iss").getString(), "madf");
    // ECDSA uses random nonce value, so the signature is always different and it is impossible to check its correctness by simple comparison. Due to the nature of ECDSA, non-random none makes possible recovery of the private key.
    // There is an RFS 6979 which provide ECDSA algorithm with deterministic nonce that solves problem of private key recovery.
    auto token = jwt.token("ecdsa-256-key-pair.pem");
    auto part = token.substr(0, 56);
    BOOST_CHECK(part == token256PartOrder1 || part == token256PartOrder2);
}

BOOST_AUTO_TEST_CASE(TestCtor384)
{
    JWTXX::JWT jwt(JWTXX::Algorithm::ES384, {{"iss", Value("madf")}});

    BOOST_CHECK_EQUAL(jwt.alg(), JWTXX::Algorithm::ES384);
    BOOST_CHECK(!jwt.claims().empty());
    BOOST_CHECK(!jwt.header().empty());
    auto header = jwt.header();
    BOOST_CHECK_EQUAL(header["alg"].getString(), "ES384");
    BOOST_CHECK_EQUAL(header["typ"].getString(), "JWT");
    BOOST_CHECK_EQUAL(jwt.claim("iss").getString(), "madf");
    // ECDSA uses random nonce value, so the signature is always different and it is impossible to check its correctness by simple comparison. Due to the nature of ECDSA, non-random none makes possible recovery of the private key.
    // There is an RFS 6979 which provide ECDSA algorithm with deterministic nonce that solves problem of private key recovery.
    auto token = jwt.token("ecdsa-256-key-pair.pem");
    auto part = token.substr(0, 56);
    BOOST_CHECK(part == token384PartOrder1 || part == token384PartOrder2);
}

BOOST_AUTO_TEST_CASE(TestCtor512)
{
    JWTXX::JWT jwt(JWTXX::Algorithm::ES512, {{"iss", Value("madf")}});

    BOOST_CHECK_EQUAL(jwt.alg(), JWTXX::Algorithm::ES512);
    BOOST_CHECK(!jwt.claims().empty());
    BOOST_CHECK(!jwt.header().empty());
    auto header = jwt.header();
    BOOST_CHECK_EQUAL(header["alg"].getString(), "ES512");
    BOOST_CHECK_EQUAL(header["typ"].getString(), "JWT");
    BOOST_CHECK_EQUAL(jwt.claim("iss").getString(), "madf");
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
    BOOST_CHECK_EQUAL(header["alg"].getString(), "ES256");
    BOOST_CHECK_EQUAL(header["typ"].getString(), "JWT");
    BOOST_CHECK_EQUAL(jwt.claim("iss").getString(), "madf");
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
    BOOST_CHECK_EQUAL(header["alg"].getString(), "ES256");
    BOOST_CHECK_EQUAL(header["typ"].getString(), "JWT");
    BOOST_CHECK_EQUAL(jwt.claim("iss").getString(), "madf");
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
    BOOST_CHECK_EQUAL(header["alg"].getString(), "ES384");
    BOOST_CHECK_EQUAL(header["typ"].getString(), "JWT");
    BOOST_CHECK_EQUAL(jwt.claim("iss").getString(), "madf");
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
    BOOST_CHECK_EQUAL(header["alg"].getString(), "ES384");
    BOOST_CHECK_EQUAL(header["typ"].getString(), "JWT");
    BOOST_CHECK_EQUAL(jwt.claim("iss").getString(), "madf");
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
    BOOST_CHECK_EQUAL(header["alg"].getString(), "ES512");
    BOOST_CHECK_EQUAL(header["typ"].getString(), "JWT");
    BOOST_CHECK_EQUAL(jwt.claim("iss").getString(), "madf");
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
    BOOST_CHECK_EQUAL(header["alg"].getString(), "ES512");
    BOOST_CHECK_EQUAL(header["typ"].getString(), "JWT");
    BOOST_CHECK_EQUAL(jwt.claim("iss").getString(), "madf");
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
    BOOST_CHECK_EQUAL(header["alg"].getString(), "ES256");
    BOOST_CHECK_EQUAL(header["typ"].getString(), "JWT");
    BOOST_CHECK_EQUAL(jwt.claim("iss").getString(), "madf");
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
    BOOST_CHECK_EQUAL(header["alg"].getString(), "ES256");
    BOOST_CHECK_EQUAL(header["typ"].getString(), "JWT");
    BOOST_CHECK_EQUAL(jwt.claim("iss").getString(), "madf");
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
    BOOST_CHECK_EQUAL(header["alg"].getString(), "ES384");
    BOOST_CHECK_EQUAL(header["typ"].getString(), "JWT");
    BOOST_CHECK_EQUAL(jwt.claim("iss").getString(), "madf");
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
    BOOST_CHECK_EQUAL(header["alg"].getString(), "ES384");
    BOOST_CHECK_EQUAL(header["typ"].getString(), "JWT");
    BOOST_CHECK_EQUAL(jwt.claim("iss").getString(), "madf");
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
    BOOST_CHECK_EQUAL(header["alg"].getString(), "ES512");
    BOOST_CHECK_EQUAL(header["typ"].getString(), "JWT");
    BOOST_CHECK_EQUAL(jwt.claim("iss").getString(), "madf");
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
    BOOST_CHECK_EQUAL(header["alg"].getString(), "ES512");
    BOOST_CHECK_EQUAL(header["typ"].getString(), "JWT");
    BOOST_CHECK_EQUAL(jwt.claim("iss").getString(), "madf");
    // ECDSA uses random nonce value, so the signature is always different and it is impossible to check its correctness by simple comparison. Due to the nature of ECDSA, non-random none makes possible recovery of the private key.
    // There is an RFS 6979 which provide ECDSA algorithm with deterministic nonce that solves problem of private key recovery.
    auto token = jwt.token("ecdsa-256-key-pair.pem");
    auto part = token.substr(0, 56);
    BOOST_CHECK(part == token512PartOrder1 || part == token512PartOrder2);
}

BOOST_AUTO_TEST_CASE(TestVerifier)
{
    BOOST_CHECK(JWTXX::JWT::verify(token512Order2, JWTXX::Key(JWTXX::Algorithm::ES512, "public-ecdsa-256-key.pem")));
    BOOST_CHECK(JWTXX::JWT::verify(token512Order2, JWTXX::Key(JWTXX::Algorithm::ES512, publicecdsa256keydata)));
    BOOST_CHECK(JWTXX::JWT::verify(tokenWithExp, JWTXX::Key(JWTXX::Algorithm::ES256, "public-ecdsa-256-key.pem"), {JWTXX::Validate::exp(1475246522)}));
    BOOST_CHECK(!JWTXX::JWT::verify(tokenWithExp, JWTXX::Key(JWTXX::Algorithm::ES256, "public-ecdsa-256-key.pem"), {JWTXX::Validate::exp(1475246524)}));
    BOOST_CHECK(!JWTXX::JWT::verify(tokenWithExp, JWTXX::Key(JWTXX::Algorithm::ES256, "public-ecdsa-256-key.pem"), {JWTXX::Validate::iat(1475242922)}));
    BOOST_CHECK(JWTXX::JWT::verify(tokenWithExp, JWTXX::Key(JWTXX::Algorithm::ES256, "public-ecdsa-256-key.pem"), {JWTXX::Validate::iat(1475242924)}));
    BOOST_CHECK(!JWTXX::JWT::verify(tokenWithExp, JWTXX::Key(JWTXX::Algorithm::ES256, "public-ecdsa-256-key.pem"), {JWTXX::Validate::nbf(1475242922)}));
    BOOST_CHECK(JWTXX::JWT::verify(tokenWithExp, JWTXX::Key(JWTXX::Algorithm::ES256, "public-ecdsa-256-key.pem"), {JWTXX::Validate::nbf(1475242924)}));
    BOOST_CHECK(JWTXX::JWT::verify(tokenWithExp, JWTXX::Key(JWTXX::Algorithm::ES256, "public-ecdsa-256-key.pem"), {JWTXX::Validate::exp(1475246522), JWTXX::Validate::iat(1475246522), JWTXX::Validate::nbf(1475246522)}));
    BOOST_CHECK(!JWTXX::JWT::verify(tokenWithExp, JWTXX::Key(JWTXX::Algorithm::ES256, "public-ecdsa-256-key.pem"), {JWTXX::Validate::exp(1475246524), JWTXX::Validate::iat(1475246524), JWTXX::Validate::nbf(1475246524)}));
    BOOST_CHECK(!JWTXX::JWT::verify(tokenWithExp, JWTXX::Key(JWTXX::Algorithm::ES256, "public-ecdsa-256-key.pem"), {JWTXX::Validate::exp(1475242922), JWTXX::Validate::iat(1475242922), JWTXX::Validate::nbf(1475242922)}));
    BOOST_CHECK(JWTXX::JWT::verify(tokenWithExp, JWTXX::Key(JWTXX::Algorithm::ES256, "public-ecdsa-256-key.pem"), {JWTXX::Validate::iss("madf")}));
    BOOST_CHECK(!JWTXX::JWT::verify(tokenWithExp, JWTXX::Key(JWTXX::Algorithm::ES256, "public-ecdsa-256-key.pem"), {JWTXX::Validate::iss("somebody")}));
    BOOST_CHECK(JWTXX::JWT::verify(tokenWithExp, JWTXX::Key(JWTXX::Algorithm::ES256, "public-ecdsa-256-key.pem"), {JWTXX::Validate::sub("user")}));
    BOOST_CHECK(!JWTXX::JWT::verify(tokenWithExp, JWTXX::Key(JWTXX::Algorithm::ES256, "public-ecdsa-256-key.pem"), {JWTXX::Validate::sub("someone")}));
    BOOST_CHECK(JWTXX::JWT::verify(tokenWithExp, JWTXX::Key(JWTXX::Algorithm::ES256, "public-ecdsa-256-key.pem"), {JWTXX::Validate::aud("")}));
    BOOST_CHECK(JWTXX::JWT::verify(tokenWithExp, JWTXX::Key(JWTXX::Algorithm::ES256, "public-ecdsa-256-key.pem"), {JWTXX::Validate::aud("something")})); // Audience is missing in the token
    BOOST_CHECK(!JWTXX::JWT::verify(token512Order2, JWTXX::Key(JWTXX::Algorithm::ES512, "")));
    BOOST_CHECK(!JWTXX::JWT::verify(token512Order2, JWTXX::Key(JWTXX::Algorithm::ES512, "abc")));
}

BOOST_AUTO_TEST_CASE(TestParserNoVerify)
{
    auto jwt1 = JWTXX::JWT::parse(token512Order1);
    BOOST_CHECK_EQUAL(jwt1.alg(), JWTXX::Algorithm::ES512);
    auto jwt2 = JWTXX::JWT::parse(token512Order1);
    BOOST_CHECK_EQUAL(jwt2.alg(), JWTXX::Algorithm::ES512);

    auto jwt = JWTXX::JWT::parse(tokenWithExp);
    BOOST_CHECK_EQUAL(jwt.alg(), JWTXX::Algorithm::ES256);
    BOOST_CHECK_EQUAL(jwt.claim("iss").getString(), "madf");
    BOOST_CHECK_EQUAL(jwt.claim("sub").getString(), "user");
    BOOST_CHECK_EQUAL(jwt.claim("exp").getInteger(), 1475246523);
    BOOST_CHECK_EQUAL(jwt.claim("iat").getInteger(), 1475242923);
    BOOST_CHECK_EQUAL(jwt.claim("nbf").getInteger(), 1475242923);
}

BOOST_AUTO_TEST_CASE(TestParserNoVerifyCorruptedSignature)
{
    auto jwt = JWTXX::JWT::parse(token512CorruptedSignature);
    BOOST_CHECK_EQUAL(jwt.alg(), JWTXX::Algorithm::ES512);
}

BOOST_AUTO_TEST_CASE(TestParserExtraVerification)
{
    JWTXX::JWT jwt(tokenWithExp, JWTXX::Key(JWTXX::Algorithm::ES256, "public-ecdsa-256-key.pem"), {JWTXX::Validate::exp(1475246522), JWTXX::Validate::iat(1475246522), JWTXX::Validate::nbf(1475246522)});
    BOOST_CHECK_EQUAL(jwt.alg(), JWTXX::Algorithm::ES256);
    BOOST_CHECK_EQUAL(jwt.claim("iss").getString(), "madf");
    BOOST_CHECK_EQUAL(jwt.claim("sub").getString(), "user");
    BOOST_CHECK_EQUAL(jwt.claim("exp").getInteger(), 1475246523);
    BOOST_CHECK_EQUAL(jwt.claim("iat").getInteger(), 1475242923);
    BOOST_CHECK_EQUAL(jwt.claim("nbf").getInteger(), 1475242923);
    BOOST_CHECK_THROW(JWTXX::JWT(token512CorruptedSignature, JWTXX::Key(JWTXX::Algorithm::ES512, "ecdsa-cert.pem")), JWTXX::JWT::ValidationError);
    BOOST_CHECK_THROW(JWTXX::JWT(tokenWithExp, JWTXX::Key(JWTXX::Algorithm::ES256, "public-ecdsa-256-key.pem"), {JWTXX::Validate::exp(1475242922), JWTXX::Validate::iat(1475242922), JWTXX::Validate::nbf(1475242922)}), JWTXX::JWT::ValidationError);
    BOOST_CHECK_THROW(JWTXX::JWT(tokenWithExp, JWTXX::Key(JWTXX::Algorithm::ES256, "public-ecdsa-256-key.pem"), {JWTXX::Validate::exp(1475246524), JWTXX::Validate::iat(1475246524), JWTXX::Validate::nbf(1475246524)}), JWTXX::JWT::ValidationError);
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
    BOOST_CHECK_THROW(JWTXX::JWT(invalidHeaderToken, JWTXX::Key(JWTXX::Algorithm::ES256, "public-ecdsa-256-key.pem")), JWTXX::JWT::Error);
}

BOOST_AUTO_TEST_CASE(TestCtor256PwNoCallback)
{
    JWTXX::JWT jwt(JWTXX::Algorithm::ES256, {{"iss", Value("madf")}});

    BOOST_CHECK_EQUAL(jwt.alg(), JWTXX::Algorithm::ES256);
    BOOST_CHECK(!jwt.claims().empty());
    BOOST_CHECK(!jwt.header().empty());
    auto header = jwt.header();
    BOOST_CHECK_EQUAL(header["alg"].getString(), "ES256");
    BOOST_CHECK_EQUAL(header["typ"].getString(), "JWT");
    BOOST_CHECK_EQUAL(jwt.claim("iss").getString(), "madf");
    BOOST_CHECK_THROW(jwt.token("ecdsa-256-key-pair-pw.pem"), JWTXX::Key::Error);
    BOOST_CHECK_THROW(jwt.token("ecdsa-256-key-pair-pw.pem", [](){ return "abc"; }), JWTXX::Key::Error);
}

BOOST_AUTO_TEST_CASE(TestCtor256Pw)
{
    JWTXX::JWT jwt(JWTXX::Algorithm::ES256, {{"iss", Value("madf")}});

    BOOST_CHECK_EQUAL(jwt.alg(), JWTXX::Algorithm::ES256);
    BOOST_CHECK(!jwt.claims().empty());
    BOOST_CHECK(!jwt.header().empty());
    auto header = jwt.header();
    BOOST_CHECK_EQUAL(header["alg"].getString(), "ES256");
    BOOST_CHECK_EQUAL(header["typ"].getString(), "JWT");
    BOOST_CHECK_EQUAL(jwt.claim("iss").getString(), "madf");
    // ECDSA uses random nonce value, so the signature is always different and it is impossible to check its correctness by simple comparison. Due to the nature of ECDSA, non-random none makes possible recovery of the private key.
    // There is an RFS 6979 which provide ECDSA algorithm with deterministic nonce that solves problem of private key recovery.
    auto token = jwt.token("ecdsa-256-key-pair-pw.pem", [](){ return "123456"; });
    auto part = token.substr(0, 56);
    BOOST_CHECK(part == token256PartOrder1 || part == token256PartOrder2);
}

BOOST_AUTO_TEST_CASE(TestCtor384Pw)
{
    JWTXX::JWT jwt(JWTXX::Algorithm::ES384, {{"iss", Value("madf")}});

    BOOST_CHECK_EQUAL(jwt.alg(), JWTXX::Algorithm::ES384);
    BOOST_CHECK(!jwt.claims().empty());
    BOOST_CHECK(!jwt.header().empty());
    auto header = jwt.header();
    BOOST_CHECK_EQUAL(header["alg"].getString(), "ES384");
    BOOST_CHECK_EQUAL(header["typ"].getString(), "JWT");
    BOOST_CHECK_EQUAL(jwt.claim("iss").getString(), "madf");
    // ECDSA uses random nonce value, so the signature is always different and it is impossible to check its correctness by simple comparison. Due to the nature of ECDSA, non-random none makes possible recovery of the private key.
    // There is an RFS 6979 which provide ECDSA algorithm with deterministic nonce that solves problem of private key recovery.
    auto token = jwt.token("ecdsa-256-key-pair-pw.pem", [](){ return "123456"; });
    auto part = token.substr(0, 56);
    BOOST_CHECK(part == token384PartOrder1 || part == token384PartOrder2);
}

BOOST_AUTO_TEST_CASE(TestCtor512Pw)
{
    JWTXX::JWT jwt(JWTXX::Algorithm::ES512, {{"iss", Value("madf")}});

    BOOST_CHECK_EQUAL(jwt.alg(), JWTXX::Algorithm::ES512);
    BOOST_CHECK(!jwt.claims().empty());
    BOOST_CHECK(!jwt.header().empty());
    auto header = jwt.header();
    BOOST_CHECK_EQUAL(header["alg"].getString(), "ES512");
    BOOST_CHECK_EQUAL(header["typ"].getString(), "JWT");
    BOOST_CHECK_EQUAL(jwt.claim("iss").getString(), "madf");
    // ECDSA uses random nonce value, so the signature is always different and it is impossible to check its correctness by simple comparison. Due to the nature of ECDSA, non-random none makes possible recovery of the private key.
    // There is an RFS 6979 which provide ECDSA algorithm with deterministic nonce that solves problem of private key recovery.
    auto token = jwt.token("ecdsa-256-key-pair-pw.pem", [](){ return "123456"; });
    auto part = token.substr(0, 56);
    BOOST_CHECK(part == token512PartOrder1 || part == token512PartOrder2);
}
