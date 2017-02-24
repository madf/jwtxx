#include "jwtxx/jwt.h"
#include "jwtxx/ios.h"

#include "initopenssl.h"

#define BOOST_TEST_MODULE JWTRSAAlgTest

#include <boost/test/included/unit_test.hpp>

namespace
{

constexpr auto token256Order1 = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJtYWRmIn0.GpuCt3HLj3ToT8SYa-EErTgd4deISPXrAq7c_fwt3837wMtFripY1DOhEH-YLxexhFwjkHrlNRWNV7jlamS32zw4y7_lF9zlQ4AgdGOXsNPUGjPXXuCPvVr84sBGpIjki9LUFa-qTGAe1qNsCH7rwG-LF4c0BOF2tnhwXSaipgFcInoHIhoj9KQBT7kkTfmXiBTp8ITkWnWMtmVaIHay6Z3aiOu-jRDWPlzoIWwLVfAPL9ti8uKzMmUGGhpiwPgwZnIoPVgyjM6U0ahHr_tEeeBYCa-7J8gYPEpXK1TkOQq1uUpk52LbrsieZMpsSTbbybGwBmBl2FBC3tjjCc8tug";
constexpr auto token256Order2 = "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJtYWRmIn0.gO-HSMMeWKCmB3xFo7pvFWVNxpo17mWTKv9H2giWXJUQhzNOc2PSxhElrz7swGmpo9m7NShGueF-SlRDBgq8olgX_NDOvzvXSlVusZg8COU_PkxEd_NolEIlAoIGXGwFfpVUiv5VY_kV2vvONns1Sifr5cJ1wIbtONhpI4B0GntvBoQCq9XgbmgRN_0pOEuMs9p4xw1FXdWXv1wgrgceHJ-1QTCRXAhA9TRAxn_MNvb2Y5ftj4j_f6FsXA4xrurNOolcNgS9Fi8xhQEJVe3nwF_RIfSdHE3F5EPDvxYX6-ce-C6Acg1acwad8LEEaYpIOIgYvyJa3nmh_2hxuEGm8g";
constexpr auto token384Order1 = "eyJhbGciOiJSUzM4NCIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJtYWRmIn0.s8DCHwP41dmCmeXSs6cUJRAFtQqOfTtk1S54MlH06By98ybpWzhY_lAwEAI4-QAIRoPvkZPtF03Qn1ZX1pETfDKk96zPTm8mojjpBfuO-LZgiQDcStf5hByhV4YBKYY5kNfuCuGBOdtPer7Uv-41aVyoIkGhNW-YwtHM3noBaWTP6igZHztKlQs816vEFQlNp_sA5yQk7qhlhHkAAFec1Db1apQke3MGn7m1wKh16CU4lscLDFze6S80WuXwBot1ksthvutYYTeRnIHeLz3ty9pGtaVBGW8EbcaDj2biBhVHRTiOS1oeZ-O8h2Nn9sDaV5_S2OHf3BTgLOZNbih5uQ";
constexpr auto token384Order2 = "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzM4NCJ9.eyJpc3MiOiJtYWRmIn0.tU5SWVRjc2BgVdZN4heYolUFhDIc9dHOxw7zYFstZKwEbj_K_9IRsl2kJ9Nw4NXGBntkBMIp6U1cqW9xkgiH1u4IAalL0q0NBIOW5-JEqUO65iDaDLkObJY65tbDT2q-CpsCBlYpULcWaZWj-3Xjn3Z0oTItjn40c4BJ8Ra0MaKDRKZNMScMnV7mHKylsPe-0aiRWK5QMaW_4KUjKmcJHpqY0aCA1yov1RLauPhXFC3w4KU_BbLJN25fMkSNwapmPKC2NQxuGjQRglAlq-XbxMe1FKieLPGCAPJLkzm9BHkZ0mmm405jVCfxEAw5DOVRrP5xo_2mpOxjIbBXJFPWMg";
constexpr auto token512Order1 = "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzUxMiJ9.eyJpc3MiOiJtYWRmIn0.G8vv-IyeoIg5SWcN1Qb3-9kLPr8tnUSbBPO32Srvce04Lfe0sEWmlbBD5FR7dTYtpd2iMLwu7ytFsb0n_pOD1_ti_XAytQvJH6w6pL0saABs8y_Gj1AWONfIqGGw-2ChgItUsGpHt3yr7i4gV6bKYtU2KFcwFQ3c7bXpLjV9paptLQNwOHTjadmNcuexV443pz1NlaOP9DUjTzO2WNaiAokNtJ4wh6Emdjors844p4bCnah0o4STUYbcvRILYMVIpxrew7lcrLiA-vF8kD-Pxeb_Gna8sTIQ3gx7K1fL10Mg0wPEake4Qko29gy8AXx1qki5hEYx9Pe8CxezBfyFmA";
constexpr auto token512Order2 = "eyJhbGciOiJSUzUxMiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJtYWRmIn0.fyDpJVopst2qpHzs63NRWZ9zY04KrxfQmiF0zt3i-ACB38hnBo90r_PlrhMiMU8HU52_JxcBUAi5lSQHakX16EQyR0pEwZZfoCbeI0lOzpt0yrXAYyGvJC8WlE1Mm9Ehd8iUgcvvc9nL0_gRT-4RSU7kVOHOlwIRiN6fE28si22Jjtb5hf0KjebLj7BTeNnVB17SK9qMMn7VuYtRKj767FDpnZuOwNkDvb2qeL3IzbJnTYgpOVMoinHWAvR_innn9BjzCOEkFqgj6KKzQiEbVI6tbHfD-qOHHVDF1a0eERtCUuu92LesUyWJj3etgnmmNFI5EVjDtQkldQuuFgARUw";
constexpr auto tokenCorruptedSign = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c2VyIiwiaXNzIjoibWFkZiIsImlhdCI6MTQ3NTI0MjkyMywibmJmIjoxNDc1MjQyOTIzLCJleHAiOjE0NzUyNDY1MjN9.r8mj1m0XYra8hRg2e-E85N75gEGAWbcqIMjQunFleW9XmbqAdC9YYKbfLQRe0MTXTYjP4lsfZdo7fWW93dTOpA5IpcPKAZe53GPozs1bz7GvscElUrXusVR345v4TiCk_CTAvr6DqX5o44i6OP9og5lgguXja-u_UvormjeUTA1ASM3vsQ1mTmUx8iUExnmrXrAtgtSZe_a1ebOYmZd0-cpA82zT8BlrJes_Po35Qwe3wmtvY5EZBwpT6bgEss9QOuUtqXIVZYp0HhkfD5dkpzbS9j60bxlYfb7iVDPLRx1_1iLa7ehja-kkGOvcmJcFL-";
constexpr auto tokenWithExp = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c2VyIiwiaXNzIjoibWFkZiIsImlhdCI6MTQ3NTI0MjkyMywibmJmIjoxNDc1MjQyOTIzLCJleHAiOjE0NzUyNDY1MjN9.r8mj1m0XYra8hRg2e-E85N75gEGAWbcqIMjQunFleW9XmbqAdC9YYKbfLQRe0MTXTYjP4lsfZdo7fWW93dTOpA5IpcPKAZe53GPozs1bz7GvscElUrXusVR345v4TiCk_CTAvr6DqX5o44i6OP9og5lgguXja-u_UvormjeUTA1ASM3vsQ1mTmUx8iUExnmrXrAtgtSZe_a1ebOYmZd0-cpA82zT8BlrJes_Po35Qwe3wmtvY5EZBwpT6bgEss9QOuUtqXIVZYp0HhkfD5dkpzbS9j60bxlYfb7iVDPLRx1_1iLa7ehja-kkGOvcmJcFL-KxbZ9EjHAnVsB7jtDt3A";
constexpr auto brokenTokenWithExp1 = "bGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c2VyIiwiaXNzIjoibWFkZiIsImlhdCI6MTQ3NTI0MjkyMywibmJmIjoxNDc1MjQyOTIzLCJleHAiOjE0NzUyNDY1MjN9.r8mj1m0XYra8hRg2e-E85N75gEGAWbcqIMjQunFleW9XmbqAdC9YYKbfLQRe0MTXTYjP4lsfZdo7fWW93dTOpA5IpcPKAZe53GPozs1bz7GvscElUrXusVR345v4TiCk_CTAvr6DqX5o44i6OP9og5lgguXja-u_UvormjeUTA1ASM3vsQ1mTmUx8iUExnmrXrAtgtSZe_a1ebOYmZd0-cpA82zT8BlrJes_Po35Qwe3wmtvY5EZBwpT6bgEss9QOuUtqXIVZYp0HhkfD5dkpzbS9j60bxlYfb7iVDPLRx1_1iLa7ehja-kkGOvcmJcFL-KxbZ9EjHAnVsB7jtDt3A";
constexpr auto brokenTokenWithExp2 = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.dWIiOiJ1c2VyIiwiaXNzIjoibWFkZiIsImlhdCI6MTQ3NTI0MjkyMywibmJmIjoxNDc1MjQyOTIzLCJleHAiOjE0NzUyNDY1MjN9.r8mj1m0XYra8hRg2e-E85N75gEGAWbcqIMjQunFleW9XmbqAdC9YYKbfLQRe0MTXTYjP4lsfZdo7fWW93dTOpA5IpcPKAZe53GPozs1bz7GvscElUrXusVR345v4TiCk_CTAvr6DqX5o44i6OP9og5lgguXja-u_UvormjeUTA1ASM3vsQ1mTmUx8iUExnmrXrAtgtSZe_a1ebOYmZd0-cpA82zT8BlrJes_Po35Qwe3wmtvY5EZBwpT6bgEss9QOuUtqXIVZYp0HhkfD5dkpzbS9j60bxlYfb7iVDPLRx1_1iLa7ehja-kkGOvcmJcFL-KxbZ9EjHAnVsB7jtDt3A";
constexpr auto notAToken1 = "";
constexpr auto notAToken2 = "Hello, World!";
constexpr auto invalidHeaderToken = "eyJhbGciOiJSUzI1NyIsInR5cCI6IkpXIn0.eyJuYW1lIjoiZm9vIn0.siCZKFuTEx4maNq0nhxiG1GGnDEdeN3w-ZZ6IG7gShqxhJpZbrl9yuWZQuxspDyD1gdiVR0FwhUuBptUfuDZka8C9uJWF-bRPBAExp6f3WINM0qKTcvHgSchCbPGDtxoiMbkp0Xl7vbLdkA0ojSglJb-yC90qSOYc3nbr8kVcNDt5r3-N1RupVnjyFEGgad5YP22KCD1Pqj9LkX0I112ZiCEN03Bxmps7NKw983DbvLwbeHcyZH-WJbLh43wnX_aLZ0UZ-TbLsJ4ob5I6odmiEeSPTZM3XOlVsvmai5XATdTjXzA9uR_VGh1hbGclikFMwQ9hKJfmBZIPYelmSbJzg";

}

BOOST_GLOBAL_FIXTURE(InitOpenSSL);

BOOST_AUTO_TEST_CASE(TestCtor256)
{
    JWTXX::JWT jwt(JWTXX::Algorithm::RS256, {{"iss", "madf"}});

    BOOST_CHECK_EQUAL(jwt.alg(), JWTXX::Algorithm::RS256);
    BOOST_CHECK(!jwt.claims().empty());
    BOOST_CHECK(!jwt.header().empty());
    auto header = jwt.header();
    BOOST_CHECK_EQUAL(header["alg"], "RS256");
    BOOST_CHECK_EQUAL(header["typ"], "JWT");
    BOOST_CHECK_EQUAL(jwt.claim("iss"), "madf");
    auto token = jwt.token("rsa-2048-key-pair.pem");
    // Jansson uses hashtables form JSON objects and hash function implementation reads over the boundary of the string, yet word-aligned, so actual order of header fields and claims is undefined.
    BOOST_CHECK(token == token256Order1 || token == token256Order2);
}

BOOST_AUTO_TEST_CASE(TestCtor384)
{
    JWTXX::JWT jwt(JWTXX::Algorithm::RS384, {{"iss", "madf"}});

    BOOST_CHECK_EQUAL(jwt.alg(), JWTXX::Algorithm::RS384);
    BOOST_CHECK(!jwt.claims().empty());
    BOOST_CHECK(!jwt.header().empty());
    auto header = jwt.header();
    BOOST_CHECK_EQUAL(header["alg"], "RS384");
    BOOST_CHECK_EQUAL(header["typ"], "JWT");
    BOOST_CHECK_EQUAL(jwt.claim("iss"), "madf");
    auto token = jwt.token("rsa-2048-key-pair.pem");
    // Jansson uses hashtables form JSON objects and hash function implementation reads over the boundary of the string, yet word-aligned, so actual order of header fields and claims is undefined.
    BOOST_CHECK(token == token384Order1 || token == token384Order2);
}

BOOST_AUTO_TEST_CASE(TestCtor512)
{
    JWTXX::JWT jwt(JWTXX::Algorithm::RS512, {{"iss", "madf"}});

    BOOST_CHECK_EQUAL(jwt.alg(), JWTXX::Algorithm::RS512);
    BOOST_CHECK(!jwt.claims().empty());
    BOOST_CHECK(!jwt.header().empty());
    auto header = jwt.header();
    BOOST_CHECK_EQUAL(header["alg"], "RS512");
    BOOST_CHECK_EQUAL(header["typ"], "JWT");
    BOOST_CHECK_EQUAL(jwt.claim("iss"), "madf");
    auto token = jwt.token("rsa-2048-key-pair.pem");
    // Jansson uses hashtables form JSON objects and hash function implementation reads over the boundary of the string, yet word-aligned, so actual order of header fields and claims is undefined.
    BOOST_CHECK(token == token512Order1 || token == token512Order2);
}

BOOST_AUTO_TEST_CASE(TestParser256)
{
    JWTXX::JWT jwt(token256Order1, JWTXX::Key(JWTXX::Algorithm::RS256, "public-rsa-2048-key.pem"));

    BOOST_CHECK_EQUAL(jwt.alg(), JWTXX::Algorithm::RS256);
    BOOST_CHECK(!jwt.claims().empty());
    BOOST_CHECK(!jwt.header().empty());
    auto header = jwt.header();
    BOOST_CHECK_EQUAL(header["alg"], "RS256");
    BOOST_CHECK_EQUAL(header["typ"], "JWT");
    BOOST_CHECK_EQUAL(jwt.claim("iss"), "madf");
    auto token = jwt.token("rsa-2048-key-pair.pem");
    // Jansson uses hashtables form JSON objects and hash function implementation reads over the boundary of the string, yet word-aligned, so actual order of header fields and claims is undefined.
    BOOST_CHECK(token == token256Order1 || token == token256Order2);
}

BOOST_AUTO_TEST_CASE(TestParserDifferentFieldOrder256)
{
    JWTXX::JWT jwt(token256Order2, JWTXX::Key(JWTXX::Algorithm::RS256, "public-rsa-2048-key.pem"));

    BOOST_CHECK_EQUAL(jwt.alg(), JWTXX::Algorithm::RS256);
    BOOST_CHECK(!jwt.claims().empty());
    BOOST_CHECK(!jwt.header().empty());
    auto header = jwt.header();
    BOOST_CHECK_EQUAL(header["alg"], "RS256");
    BOOST_CHECK_EQUAL(header["typ"], "JWT");
    BOOST_CHECK_EQUAL(jwt.claim("iss"), "madf");
    auto token = jwt.token("rsa-2048-key-pair.pem");
    // Jansson uses hashtables form JSON objects and hash function implementation reads over the boundary of the string, yet word-aligned, so actual order of header fields and claims is undefined.
    BOOST_CHECK(token == token256Order1 || token == token256Order2);
}

BOOST_AUTO_TEST_CASE(TestParser384)
{
    JWTXX::JWT jwt(token384Order1, JWTXX::Key(JWTXX::Algorithm::RS384, "public-rsa-2048-key.pem"));

    BOOST_CHECK_EQUAL(jwt.alg(), JWTXX::Algorithm::RS384);
    BOOST_CHECK(!jwt.claims().empty());
    BOOST_CHECK(!jwt.header().empty());
    auto header = jwt.header();
    BOOST_CHECK_EQUAL(header["alg"], "RS384");
    BOOST_CHECK_EQUAL(header["typ"], "JWT");
    BOOST_CHECK_EQUAL(jwt.claim("iss"), "madf");
    auto token = jwt.token("rsa-2048-key-pair.pem");
    // Jansson uses hashtables form JSON objects and hash function implementation reads over the boundary of the string, yet word-aligned, so actual order of header fields and claims is undefined.
    BOOST_CHECK(token == token384Order1 || token == token384Order2);
}

BOOST_AUTO_TEST_CASE(TestParserDifferentFieldOrder384)
{
    JWTXX::JWT jwt(token384Order2, JWTXX::Key(JWTXX::Algorithm::RS384, "public-rsa-2048-key.pem"));

    BOOST_CHECK_EQUAL(jwt.alg(), JWTXX::Algorithm::RS384);
    BOOST_CHECK(!jwt.claims().empty());
    BOOST_CHECK(!jwt.header().empty());
    auto header = jwt.header();
    BOOST_CHECK_EQUAL(header["alg"], "RS384");
    BOOST_CHECK_EQUAL(header["typ"], "JWT");
    BOOST_CHECK_EQUAL(jwt.claim("iss"), "madf");
    auto token = jwt.token("rsa-2048-key-pair.pem");
    // Jansson uses hashtables form JSON objects and hash function implementation reads over the boundary of the string, yet word-aligned, so actual order of header fields and claims is undefined.
    BOOST_CHECK(token == token384Order1 || token == token384Order2);
}

BOOST_AUTO_TEST_CASE(TestParser512)
{
    JWTXX::JWT jwt(token512Order1, JWTXX::Key(JWTXX::Algorithm::RS512, "public-rsa-2048-key.pem"));

    BOOST_CHECK_EQUAL(jwt.alg(), JWTXX::Algorithm::RS512);
    BOOST_CHECK(!jwt.claims().empty());
    BOOST_CHECK(!jwt.header().empty());
    auto header = jwt.header();
    BOOST_CHECK_EQUAL(header["alg"], "RS512");
    BOOST_CHECK_EQUAL(header["typ"], "JWT");
    BOOST_CHECK_EQUAL(jwt.claim("iss"), "madf");
    auto token = jwt.token("rsa-2048-key-pair.pem");
    // Jansson uses hashtables form JSON objects and hash function implementation reads over the boundary of the string, yet word-aligned, so actual order of header fields and claims is undefined.
    BOOST_CHECK(token == token512Order1 || token == token512Order2);
}

BOOST_AUTO_TEST_CASE(TestParserDifferentFieldOrder512)
{
    JWTXX::JWT jwt(token512Order2, JWTXX::Key(JWTXX::Algorithm::RS512, "public-rsa-2048-key.pem"));

    BOOST_CHECK_EQUAL(jwt.alg(), JWTXX::Algorithm::RS512);
    BOOST_CHECK(!jwt.claims().empty());
    BOOST_CHECK(!jwt.header().empty());
    auto header = jwt.header();
    BOOST_CHECK_EQUAL(header["alg"], "RS512");
    BOOST_CHECK_EQUAL(header["typ"], "JWT");
    BOOST_CHECK_EQUAL(jwt.claim("iss"), "madf");
    auto token = jwt.token("rsa-2048-key-pair.pem");
    // Jansson uses hashtables form JSON objects and hash function implementation reads over the boundary of the string, yet word-aligned, so actual order of header fields and claims is undefined.
    BOOST_CHECK(token == token512Order1 || token == token512Order2);
}

BOOST_AUTO_TEST_CASE(TestParserWithCert256)
{
    JWTXX::JWT jwt(token256Order1, JWTXX::Key(JWTXX::Algorithm::RS256, "rsa-cert.pem"));

    BOOST_CHECK_EQUAL(jwt.alg(), JWTXX::Algorithm::RS256);
    BOOST_CHECK(!jwt.claims().empty());
    BOOST_CHECK(!jwt.header().empty());
    auto header = jwt.header();
    BOOST_CHECK_EQUAL(header["alg"], "RS256");
    BOOST_CHECK_EQUAL(header["typ"], "JWT");
    BOOST_CHECK_EQUAL(jwt.claim("iss"), "madf");
    auto token = jwt.token("rsa-2048-key-pair.pem");
    // Jansson uses hashtables form JSON objects and hash function implementation reads over the boundary of the string, yet word-aligned, so actual order of header fields and claims is undefined.
    BOOST_CHECK(token == token256Order1 || token == token256Order2);
}

BOOST_AUTO_TEST_CASE(TestParserWithCertDifferentFieldOrder256)
{
    JWTXX::JWT jwt(token256Order2, JWTXX::Key(JWTXX::Algorithm::RS256, "rsa-cert.pem"));

    BOOST_CHECK_EQUAL(jwt.alg(), JWTXX::Algorithm::RS256);
    BOOST_CHECK(!jwt.claims().empty());
    BOOST_CHECK(!jwt.header().empty());
    auto header = jwt.header();
    BOOST_CHECK_EQUAL(header["alg"], "RS256");
    BOOST_CHECK_EQUAL(header["typ"], "JWT");
    BOOST_CHECK_EQUAL(jwt.claim("iss"), "madf");
    auto token = jwt.token("rsa-2048-key-pair.pem");
    // Jansson uses hashtables form JSON objects and hash function implementation reads over the boundary of the string, yet word-aligned, so actual order of header fields and claims is undefined.
    BOOST_CHECK(token == token256Order1 || token == token256Order2);
}

BOOST_AUTO_TEST_CASE(TestParserWithCert384)
{
    JWTXX::JWT jwt(token384Order1, JWTXX::Key(JWTXX::Algorithm::RS384, "rsa-cert.pem"));

    BOOST_CHECK_EQUAL(jwt.alg(), JWTXX::Algorithm::RS384);
    BOOST_CHECK(!jwt.claims().empty());
    BOOST_CHECK(!jwt.header().empty());
    auto header = jwt.header();
    BOOST_CHECK_EQUAL(header["alg"], "RS384");
    BOOST_CHECK_EQUAL(header["typ"], "JWT");
    BOOST_CHECK_EQUAL(jwt.claim("iss"), "madf");
    auto token = jwt.token("rsa-2048-key-pair.pem");
    // Jansson uses hashtables form JSON objects and hash function implementation reads over the boundary of the string, yet word-aligned, so actual order of header fields and claims is undefined.
    BOOST_CHECK(token == token384Order1 || token == token384Order2);
}

BOOST_AUTO_TEST_CASE(TestParserWithCertDifferentFieldOrder384)
{
    JWTXX::JWT jwt(token384Order2, JWTXX::Key(JWTXX::Algorithm::RS384, "rsa-cert.pem"));

    BOOST_CHECK_EQUAL(jwt.alg(), JWTXX::Algorithm::RS384);
    BOOST_CHECK(!jwt.claims().empty());
    BOOST_CHECK(!jwt.header().empty());
    auto header = jwt.header();
    BOOST_CHECK_EQUAL(header["alg"], "RS384");
    BOOST_CHECK_EQUAL(header["typ"], "JWT");
    BOOST_CHECK_EQUAL(jwt.claim("iss"), "madf");
    auto token = jwt.token("rsa-2048-key-pair.pem");
    // Jansson uses hashtables form JSON objects and hash function implementation reads over the boundary of the string, yet word-aligned, so actual order of header fields and claims is undefined.
    BOOST_CHECK(token == token384Order1 || token == token384Order2);
}

BOOST_AUTO_TEST_CASE(TestParserWithCert512)
{
    JWTXX::JWT jwt(token512Order1, JWTXX::Key(JWTXX::Algorithm::RS512, "rsa-cert.pem"));

    BOOST_CHECK_EQUAL(jwt.alg(), JWTXX::Algorithm::RS512);
    BOOST_CHECK(!jwt.claims().empty());
    BOOST_CHECK(!jwt.header().empty());
    auto header = jwt.header();
    BOOST_CHECK_EQUAL(header["alg"], "RS512");
    BOOST_CHECK_EQUAL(header["typ"], "JWT");
    BOOST_CHECK_EQUAL(jwt.claim("iss"), "madf");
    auto token = jwt.token("rsa-2048-key-pair.pem");
    // Jansson uses hashtables form JSON objects and hash function implementation reads over the boundary of the string, yet word-aligned, so actual order of header fields and claims is undefined.
    BOOST_CHECK(token == token512Order1 || token == token512Order2);
}

BOOST_AUTO_TEST_CASE(TestParserWithCertDifferentFieldOrder512)
{
    JWTXX::JWT jwt(token512Order2, JWTXX::Key(JWTXX::Algorithm::RS512, "rsa-cert.pem"));

    BOOST_CHECK_EQUAL(jwt.alg(), JWTXX::Algorithm::RS512);
    BOOST_CHECK(!jwt.claims().empty());
    BOOST_CHECK(!jwt.header().empty());
    auto header = jwt.header();
    BOOST_CHECK_EQUAL(header["alg"], "RS512");
    BOOST_CHECK_EQUAL(header["typ"], "JWT");
    BOOST_CHECK_EQUAL(jwt.claim("iss"), "madf");
    auto token = jwt.token("rsa-2048-key-pair.pem");
    // Jansson uses hashtables form JSON objects and hash function implementation reads over the boundary of the string, yet word-aligned, so actual order of header fields and claims is undefined.
    BOOST_CHECK(token == token512Order1 || token == token512Order2);
}

BOOST_AUTO_TEST_CASE(TestVerifier)
{
    BOOST_CHECK(JWTXX::JWT::verify(token512Order2, JWTXX::Key(JWTXX::Algorithm::RS512, "public-rsa-2048-key.pem")));
    BOOST_CHECK(JWTXX::JWT::verify(tokenWithExp, JWTXX::Key(JWTXX::Algorithm::RS256, "public-rsa-2048-key.pem"), {JWTXX::Validate::exp(1475246522)}));
    BOOST_CHECK(!JWTXX::JWT::verify(tokenWithExp, JWTXX::Key(JWTXX::Algorithm::RS256, "public-rsa-2048-key.pem"), {JWTXX::Validate::exp(1475246524)}));
    BOOST_CHECK(!JWTXX::JWT::verify(tokenWithExp, JWTXX::Key(JWTXX::Algorithm::RS256, "public-rsa-2048-key.pem"), {JWTXX::Validate::iat(1475242922)}));
    BOOST_CHECK(JWTXX::JWT::verify(tokenWithExp, JWTXX::Key(JWTXX::Algorithm::RS256, "public-rsa-2048-key.pem"), {JWTXX::Validate::iat(1475242924)}));
    BOOST_CHECK(!JWTXX::JWT::verify(tokenWithExp, JWTXX::Key(JWTXX::Algorithm::RS256, "public-rsa-2048-key.pem"), {JWTXX::Validate::nbf(1475242922)}));
    BOOST_CHECK(JWTXX::JWT::verify(tokenWithExp, JWTXX::Key(JWTXX::Algorithm::RS256, "public-rsa-2048-key.pem"), {JWTXX::Validate::nbf(1475242924)}));
    BOOST_CHECK(JWTXX::JWT::verify(tokenWithExp, JWTXX::Key(JWTXX::Algorithm::RS256, "public-rsa-2048-key.pem"), {JWTXX::Validate::exp(1475246522), JWTXX::Validate::iat(1475246522), JWTXX::Validate::nbf(1475246522)}));
    BOOST_CHECK(!JWTXX::JWT::verify(tokenWithExp, JWTXX::Key(JWTXX::Algorithm::RS256, "public-rsa-2048-key.pem"), {JWTXX::Validate::exp(1475246524), JWTXX::Validate::iat(1475246524), JWTXX::Validate::nbf(1475246524)}));
    BOOST_CHECK(!JWTXX::JWT::verify(tokenWithExp, JWTXX::Key(JWTXX::Algorithm::RS256, "public-rsa-2048-key.pem"), {JWTXX::Validate::exp(1475242922), JWTXX::Validate::iat(1475242922), JWTXX::Validate::nbf(1475242922)}));
    BOOST_CHECK(JWTXX::JWT::verify(tokenWithExp, JWTXX::Key(JWTXX::Algorithm::RS256, "public-rsa-2048-key.pem"), {JWTXX::Validate::iss("madf")}));
    BOOST_CHECK(!JWTXX::JWT::verify(tokenWithExp, JWTXX::Key(JWTXX::Algorithm::RS256, "public-rsa-2048-key.pem"), {JWTXX::Validate::iss("somebody")}));
    BOOST_CHECK(JWTXX::JWT::verify(tokenWithExp, JWTXX::Key(JWTXX::Algorithm::RS256, "public-rsa-2048-key.pem"), {JWTXX::Validate::sub("user")}));
    BOOST_CHECK(!JWTXX::JWT::verify(tokenWithExp, JWTXX::Key(JWTXX::Algorithm::RS256, "public-rsa-2048-key.pem"), {JWTXX::Validate::sub("someone")}));
    BOOST_CHECK(JWTXX::JWT::verify(tokenWithExp, JWTXX::Key(JWTXX::Algorithm::RS256, "public-rsa-2048-key.pem"), {JWTXX::Validate::aud("")}));
    BOOST_CHECK(JWTXX::JWT::verify(tokenWithExp, JWTXX::Key(JWTXX::Algorithm::RS256, "public-rsa-2048-key.pem"), {JWTXX::Validate::aud("something")})); // Audience is missing in the token
}

BOOST_AUTO_TEST_CASE(TestParserNoVerify)
{
    auto jwt = JWTXX::JWT::parse(tokenWithExp);
    BOOST_CHECK_EQUAL(jwt.alg(), JWTXX::Algorithm::RS256);
    BOOST_CHECK_EQUAL(jwt.claim("iss"), "madf");
    BOOST_CHECK_EQUAL(jwt.claim("sub"), "user");
    BOOST_CHECK_EQUAL(jwt.claim("exp"), "1475246523");
    BOOST_CHECK_EQUAL(jwt.claim("iat"), "1475242923");
    BOOST_CHECK_EQUAL(jwt.claim("nbf"), "1475242923");
}

BOOST_AUTO_TEST_CASE(TestParserNoVerifyCorruptedSignature)
{
    auto jwt = JWTXX::JWT::parse(tokenCorruptedSign);
    BOOST_CHECK_EQUAL(jwt.alg(), JWTXX::Algorithm::RS256);
    BOOST_CHECK_EQUAL(jwt.claim("iss"), "madf");
    BOOST_CHECK_EQUAL(jwt.claim("sub"), "user");
    BOOST_CHECK_EQUAL(jwt.claim("exp"), "1475246523");
    BOOST_CHECK_EQUAL(jwt.claim("iat"), "1475242923");
    BOOST_CHECK_EQUAL(jwt.claim("nbf"), "1475242923");
}

BOOST_AUTO_TEST_CASE(TestParserExtraVerification)
{
    JWTXX::JWT jwt(tokenWithExp, JWTXX::Key(JWTXX::Algorithm::RS256, "public-rsa-2048-key.pem"), {JWTXX::Validate::exp(1475246522), JWTXX::Validate::iat(1475246522), JWTXX::Validate::nbf(1475246522)});
    BOOST_CHECK_EQUAL(jwt.alg(), JWTXX::Algorithm::RS256);
    BOOST_CHECK_EQUAL(jwt.claim("iss"), "madf");
    BOOST_CHECK_EQUAL(jwt.claim("sub"), "user");
    BOOST_CHECK_EQUAL(jwt.claim("exp"), "1475246523");
    BOOST_CHECK_EQUAL(jwt.claim("iat"), "1475242923");
    BOOST_CHECK_EQUAL(jwt.claim("nbf"), "1475242923");
    BOOST_CHECK_THROW(JWTXX::JWT(tokenCorruptedSign, JWTXX::Key(JWTXX::Algorithm::RS256, "public-rsa-2048-key.pem")), JWTXX::JWT::ValidationError);
    BOOST_CHECK_THROW(JWTXX::JWT(tokenWithExp, JWTXX::Key(JWTXX::Algorithm::RS256, "public-rsa-2048-key.pem"), {JWTXX::Validate::exp(1475242922), JWTXX::Validate::iat(1475242922), JWTXX::Validate::nbf(1475242922)}), JWTXX::JWT::ValidationError);
    BOOST_CHECK_THROW(JWTXX::JWT(tokenWithExp, JWTXX::Key(JWTXX::Algorithm::RS256, "public-rsa-2048-key.pem"), {JWTXX::Validate::exp(1475246524), JWTXX::Validate::iat(1475246524), JWTXX::Validate::nbf(1475246524)}), JWTXX::JWT::ValidationError);
}

BOOST_AUTO_TEST_CASE(TestParserErrors)
{
    BOOST_CHECK_THROW(JWTXX::JWT(brokenTokenWithExp1, JWTXX::Key(JWTXX::Algorithm::RS256, "public-rsa-2048-key.pem"), {JWTXX::Validate::exp(1475242922), JWTXX::Validate::iat(1475242922), JWTXX::Validate::nbf(1475242922)}), JWTXX::JWT::ParseError);
    BOOST_CHECK_THROW(JWTXX::JWT(brokenTokenWithExp2, JWTXX::Key(JWTXX::Algorithm::RS256, "public-rsa-2048-key.pem"), {JWTXX::Validate::exp(1475246524), JWTXX::Validate::iat(1475246524), JWTXX::Validate::nbf(1475246524)}), JWTXX::JWT::ParseError);
    BOOST_CHECK_THROW(JWTXX::JWT(notAToken1, JWTXX::Key(JWTXX::Algorithm::RS256, "public-rsa-2048-key.pem"), {JWTXX::Validate::exp(1475242922), JWTXX::Validate::iat(1475242922), JWTXX::Validate::nbf(1475242922)}), JWTXX::JWT::ParseError);
    BOOST_CHECK_THROW(JWTXX::JWT(notAToken2, JWTXX::Key(JWTXX::Algorithm::RS256, "public-rsa-2048-key.pem"), {JWTXX::Validate::exp(1475246524), JWTXX::Validate::iat(1475246524), JWTXX::Validate::nbf(1475246524)}), JWTXX::JWT::ParseError);
}

BOOST_AUTO_TEST_CASE(TestParserHeaderErrors)
{
    BOOST_CHECK(!JWTXX::JWT::verify(invalidHeaderToken, JWTXX::Key(JWTXX::Algorithm::RS256, "public-rsa-2048-key.pem")));
    BOOST_CHECK_THROW(JWTXX::JWT(invalidHeaderToken, JWTXX::Key(JWTXX::Algorithm::RS256, "public-rsa-2048-key.pem")), JWTXX::JWT::ValidationError);
}

BOOST_AUTO_TEST_CASE(TestCtor256PwNoCallback)
{
    JWTXX::JWT jwt(JWTXX::Algorithm::RS256, {{"iss", "madf"}});

    BOOST_CHECK_EQUAL(jwt.alg(), JWTXX::Algorithm::RS256);
    BOOST_CHECK(!jwt.claims().empty());
    BOOST_CHECK(!jwt.header().empty());
    auto header = jwt.header();
    BOOST_CHECK_EQUAL(header["alg"], "RS256");
    BOOST_CHECK_EQUAL(header["typ"], "JWT");
    BOOST_CHECK_EQUAL(jwt.claim("iss"), "madf");
    BOOST_CHECK_THROW(jwt.token("rsa-2048-key-pair-pw.pem"), JWTXX::Key::Error);
    BOOST_CHECK_THROW(jwt.token("rsa-2048-key-pair-pw.pem", [](){ return "abc"; }), JWTXX::Key::Error);
}

BOOST_AUTO_TEST_CASE(TestCtor256Pw)
{
    JWTXX::JWT jwt(JWTXX::Algorithm::RS256, {{"iss", "madf"}});

    BOOST_CHECK_EQUAL(jwt.alg(), JWTXX::Algorithm::RS256);
    BOOST_CHECK(!jwt.claims().empty());
    BOOST_CHECK(!jwt.header().empty());
    auto header = jwt.header();
    BOOST_CHECK_EQUAL(header["alg"], "RS256");
    BOOST_CHECK_EQUAL(header["typ"], "JWT");
    BOOST_CHECK_EQUAL(jwt.claim("iss"), "madf");
    auto token = jwt.token("rsa-2048-key-pair-pw.pem", [](){ return "123456"; });
    // Jansson uses hashtables form JSON objects and hash function implementation reads over the boundary of the string, yet word-aligned, so actual order of header fields and claims is undefined.
    BOOST_CHECK(token == token256Order1 || token == token256Order2);
}

BOOST_AUTO_TEST_CASE(TestCtor384Pw)
{
    JWTXX::JWT jwt(JWTXX::Algorithm::RS384, {{"iss", "madf"}});

    BOOST_CHECK_EQUAL(jwt.alg(), JWTXX::Algorithm::RS384);
    BOOST_CHECK(!jwt.claims().empty());
    BOOST_CHECK(!jwt.header().empty());
    auto header = jwt.header();
    BOOST_CHECK_EQUAL(header["alg"], "RS384");
    BOOST_CHECK_EQUAL(header["typ"], "JWT");
    BOOST_CHECK_EQUAL(jwt.claim("iss"), "madf");
    auto token = jwt.token("rsa-2048-key-pair-pw.pem", [](){ return "123456"; });
    // Jansson uses hashtables form JSON objects and hash function implementation reads over the boundary of the string, yet word-aligned, so actual order of header fields and claims is undefined.
    BOOST_CHECK(token == token384Order1 || token == token384Order2);
}

BOOST_AUTO_TEST_CASE(TestCtor512Pw)
{
    JWTXX::JWT jwt(JWTXX::Algorithm::RS512, {{"iss", "madf"}});

    BOOST_CHECK_EQUAL(jwt.alg(), JWTXX::Algorithm::RS512);
    BOOST_CHECK(!jwt.claims().empty());
    BOOST_CHECK(!jwt.header().empty());
    auto header = jwt.header();
    BOOST_CHECK_EQUAL(header["alg"], "RS512");
    BOOST_CHECK_EQUAL(header["typ"], "JWT");
    BOOST_CHECK_EQUAL(jwt.claim("iss"), "madf");
    auto token = jwt.token("rsa-2048-key-pair-pw.pem", [](){ return "123456"; });
    // Jansson uses hashtables form JSON objects and hash function implementation reads over the boundary of the string, yet word-aligned, so actual order of header fields and claims is undefined.
    BOOST_CHECK(token == token512Order1 || token == token512Order2);
}
